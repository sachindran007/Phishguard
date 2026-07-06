"""
visual_scanner.py
-----------------
Visual phishing detection using Playwright (headless browser) + Gemini Vision.

Pipeline:
  URL
   ↓
  Playwright captures a full-page screenshot (PNG, in-memory)
   ↓
  Validate screenshot is not blank
   ↓
  Screenshot sent to Gemini Vision (fallback chain)
   ↓
  AI analyzes for: fake login forms, brand spoofing, credential harvesting
   ↓
  Structured JSON verdict returned

Dependencies:
  playwright  – pip install playwright && python -m playwright install chromium
  pillow      – pip install pillow
  google-generativeai (already installed)

Environment:
  GEMINI_API_KEY  – required for vision analysis

Graceful degradation:
  - Playwright not installed       → checked=False, reason="Playwright unavailable"
  - Chromium not installed         → checked=False, reason="Browser not installed"
  - Screenshot fails               → checked=False, reason="Screenshot failed"
  - Blank screenshot               → retry once, then checked=False
  - Gemini vision fails            → checked=False, reason="Vision analysis failed"
"""

from __future__ import annotations
import os
import io
import base64
import json
import re
import time
import logging
import tempfile

logger = logging.getLogger(__name__)

# ─── Vision Prompt ────────────────────────────────────────────────────────────

_VISION_PROMPT = """You are a cybersecurity expert specializing in visual phishing detection.

Analyze this screenshot of a webpage and determine if it is a phishing page.

Look specifically for:
1. Fake login forms asking for username/password/email
2. Spoofed or copied brand logos (PayPal, Google, Facebook, Apple, Microsoft, Amazon, etc.)
3. Credential harvesting forms (credit card, bank account, SSN inputs)
4. Urgent warnings designed to trick users into entering data
5. Visual cloning of legitimate websites

Respond with ONLY valid JSON (no markdown, no explanation outside JSON):
{
  "visual_threat": true or false,
  "confidence": 0-100,
  "reason": "One sentence explaining what you see or don't see",
  "detected_brands": ["brand1", "brand2"],
  "has_login_form": true or false,
  "has_payment_form": true or false
}"""


# ─── Screenshot Capture ───────────────────────────────────────────────────────

def _is_blank_image(png_bytes: bytes) -> bool:
    """Check if a screenshot is blank/white by examining pixel variance."""
    try:
        from PIL import Image
        import numpy as np
        img = Image.open(io.BytesIO(png_bytes)).convert("RGB")
        arr = np.array(img)
        # If standard deviation of all pixels is very low, it's blank
        if arr.std() < 10:
            return True
        return False
    except Exception:
        # If we can't check, assume it's okay
        return False


def _capture_screenshot(url: str, timeout_ms: int = 30000, retry: bool = True) -> bytes | None:
    """
    Use Playwright to capture a PNG screenshot of the URL.
    Waits for full page load + JS rendering.
    Returns raw PNG bytes or None on failure.
    """
    try:
        from playwright.sync_api import sync_playwright, Error as PWError
    except ImportError:
        logger.warning("[Visual Scanner] Playwright not installed.")
        return None

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox",
                      "--disable-dev-shm-usage", "--disable-gpu"],
            )
            ctx = browser.new_context(
                viewport={"width": 1366, "height": 768},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )
            page = ctx.new_page()

            try:
                page.goto(url, timeout=timeout_ms, wait_until="networkidle")
            except Exception:
                # Fallback: try with domcontentloaded if networkidle times out
                try:
                    page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                except Exception:
                    pass  # even a partial page is useful

            # Wait for JS rendering
            page.wait_for_timeout(3000)

            png_bytes = page.screenshot(full_page=True, type="png")
            browser.close()

            # Validate: check for blank screenshots
            if _is_blank_image(png_bytes):
                logger.warning("[Visual Scanner] Blank screenshot detected (%d bytes)", len(png_bytes))
                if retry:
                    logger.info("[Visual Scanner] Retrying screenshot capture...")
                    return _capture_screenshot(url, timeout_ms=timeout_ms, retry=False)
                return None

            logger.info("[Visual Scanner] Screenshot OK: %d bytes", len(png_bytes))
            return png_bytes

    except Exception as e:
        logger.warning("[Visual Scanner] Screenshot failed: %s", e)
        return None


# ─── Gemini Vision Analysis ──────────────────────────────────────────────────

# Ordered fallback chain — gemini-2.5-flash first (best quota)
_VISION_MODEL_CHAIN = [
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-flash",
]

def _analyze_screenshot(png_bytes: bytes) -> dict:
    """
    Send PNG screenshot to Gemini Vision for phishing analysis.
    Tries multiple models if quota is exhausted.
    Returns parsed JSON result or raises on failure.
    """
    import google.generativeai as genai

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set")

    genai.configure(api_key=api_key)

    image_part = {
        "mime_type": "image/png",
        "data":      base64.b64encode(png_bytes).decode(),
    }

    last_error = None
    for model_name in _VISION_MODEL_CHAIN:
        try:
            logger.info("[Visual Scanner] Trying model %s...", model_name)
            model = genai.GenerativeModel(model_name)
            response = model.generate_content([_VISION_PROMPT, image_part])
            raw_text = response.text.strip()

            # Strip possible markdown fences
            raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
            raw_text = re.sub(r"\s*```$",          "", raw_text)

            data = json.loads(raw_text.strip())
            logger.info("[Visual Scanner] Success via %s", model_name)
            return data

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("[Visual Scanner] Parse error from %s: %s", model_name, e)
            last_error = e
            break  # parsing issues won't be fixed by switching models

        except Exception as e:
            err_str = str(e)
            if "429" in err_str or "quota" in err_str.lower() or "RESOURCE_EXHAUSTED" in err_str:
                logger.warning("[Visual Scanner] Quota reached on %s, next model...", model_name)
                time.sleep(2)
                last_error = e
                continue
            # Non-quota error — don't retry
            last_error = e
            logger.warning("[Visual Scanner] %s failed: %s", model_name, e)
            break

    raise RuntimeError(f"All vision models exhausted. Last error: {last_error}")


# ─── Public API ───────────────────────────────────────────────────────────────

def scan_visual(url: str) -> dict:
    """
    Capture a screenshot of the URL and analyze it with Gemini Vision.

    Returns:
        {
          "checked":          bool,
          "visual_threat":    bool,
          "confidence":       int   (0-100),
          "reason":           str,
          "detected_brands":  list[str],
          "has_login_form":   bool,
          "has_payment_form": bool,
          "screenshot_b64":   str | None  (base64 PNG for frontend preview),
          "error":            str | None,
        }
    """
    _not_checked = {
        "checked":          False,
        "visual_threat":    False,
        "confidence":       0,
        "reason":           "",
        "detected_brands":  [],
        "has_login_form":   False,
        "has_payment_form": False,
        "screenshot_b64":   None,
        "error":            None,
    }

    # ── 1. Capture screenshot ─────────────────────────────────────────────────
    logger.info("[Visual Scanner] Capturing screenshot of %s", url)
    start = time.time()
    png_bytes = _capture_screenshot(url)
    capture_time = time.time() - start

    if not png_bytes:
        return {**_not_checked, "error": "Screenshot capture failed (blank or Playwright unavailable)."}

    screenshot_b64 = base64.b64encode(png_bytes).decode()
    logger.info(
        "[Visual Scanner] Screenshot: %d bytes, %.1fs",
        len(png_bytes), capture_time,
    )

    # ── 2. Gemini Vision analysis ─────────────────────────────────────────────
    try:
        ai_start = time.time()
        result = _analyze_screenshot(png_bytes)
        ai_time = time.time() - ai_start

        visual_threat = bool(result.get("visual_threat", False))
        confidence    = int(result.get("confidence", 0))
        reason        = str(result.get("reason", ""))
        brands        = list(result.get("detected_brands", []))
        has_login     = bool(result.get("has_login_form", False))
        has_payment   = bool(result.get("has_payment_form", False))

        logger.info(
            "[Visual Scanner] Result: threat=%s confidence=%d model_time=%.1fs reason='%s'",
            visual_threat, confidence, ai_time, reason[:80],
        )

        return {
            "checked":          True,
            "visual_threat":    visual_threat,
            "confidence":       confidence,
            "reason":           reason,
            "detected_brands":  brands,
            "has_login_form":   has_login,
            "has_payment_form": has_payment,
            "screenshot_b64":   screenshot_b64,
            "error":            None,
        }

    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("[Visual Scanner] Could not parse Gemini response: %s", e)
        return {**_not_checked, "screenshot_b64": screenshot_b64,
                "error": "AI response could not be parsed."}

    except Exception as e:
        logger.error("[Visual Scanner] Vision analysis failed: %s", e)
        return {**_not_checked, "screenshot_b64": screenshot_b64,
                "error": f"Vision analysis failed: {str(e)[:120]}"}
