"""
feature_extractor.py
--------------------
Core security analysis engine.
Extracts 8 categories of technical features from a given URL.

Every feature returns a dict:
  {
    "name":    str  – human-readable feature label
    "value":   str  – computed value or status
    "explain": str  – plain-English interpretation
  }

The module NEVER raises; any failure is caught and returned as a
graceful "error" finding so the caller always receives a full list.
"""

import re
import ssl
import socket
import datetime
import urllib.request
import math
import requests
import dns.resolver
import tldextract
import whois                    # python-whois
from urllib.parse import urlparse

from services.url_utils import (
    extract_hostname,
    is_ip_address,
    count_subdomains,
    has_special_characters,
)

# ─── Constants ────────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure", "update",
    "bank", "password", "free", "gift", "signin",
    "confirm", "paypal", "ebay", "apple", "amazon",
    "microsoft", "support", "urgent", "suspended",
]

REQUEST_TIMEOUT = 8   # seconds for HTTP/HTTPS probes
DNS_TIMEOUT     = 5   # seconds for DNS queries

# ─── Individual Feature Extractors ────────────────────────────────────────────

def check_url_length(url: str) -> dict:
    """Feature 1 – URL Length analysis."""
    length = len(url)
    if length < 54:
        status  = f"{length} characters (Normal)"
        explain = "The URL is a typical length. Shorter URLs are generally less suspicious."
    elif length < 75:
        status  = f"{length} characters (Moderate)"
        explain = "The URL is moderately long. Slightly elevated risk but not conclusive."
    else:
        status  = f"{length} characters (Very Long ⚠)"
        explain = (
            "Very long URLs are a common phishing tactic used to hide the real domain "
            "or embed redirect parameters."
        )
    return {"name": "URL Length", "value": status, "explain": explain}


def check_https(url: str) -> dict:
    """Feature 2 – HTTPS / HTTP protocol detection."""
    scheme = urlparse(url).scheme.lower()
    if scheme == "https":
        return {
            "name":    "Protocol",
            "value":   "HTTPS ✓",
            "explain": "The site uses HTTPS, meaning traffic is encrypted in transit.",
        }
    return {
        "name":    "Protocol",
        "value":   "HTTP ⚠",
        "explain": (
            "The site uses plain HTTP. No transport encryption. "
            "Legitimate services (especially those collecting credentials) always use HTTPS."
        ),
    }


def check_ssl_certificate(hostname: str) -> dict:
    """Feature 3 – SSL certificate validity check."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT),
            server_hostname=hostname,
        ) as ssock:
            cert = ssock.getpeercert()

        # Check expiry
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left  = (expire_dt - datetime.datetime.now(datetime.timezone.utc)).days
            if days_left < 0:
                return {
                    "name":    "SSL Certificate",
                    "value":   "Expired ✗",
                    "explain": f"The SSL certificate expired {abs(days_left)} day(s) ago. This is a red flag.",
                }
            return {
                "name":    "SSL Certificate",
                "value":   f"Valid (expires in {days_left} days) ✓",
                "explain": "The site has a valid SSL certificate issued by a trusted authority.",
            }

        return {
            "name":    "SSL Certificate",
            "value":   "Valid ✓",
            "explain": "SSL certificate is present and appears valid.",
        }

    except ssl.SSLCertVerificationError as e:
        return {
            "name":    "SSL Certificate",
            "value":   "Invalid / Untrusted ✗",
            "explain": f"SSL certificate verification failed: {str(e)[:120]}",
        }
    except (socket.timeout, socket.gaierror, ConnectionRefusedError):
        return {
            "name":    "SSL Certificate",
            "value":   "Not Reachable",
            "explain": "Could not connect to port 443. The site may not support HTTPS.",
        }
    except Exception as e:
        return {
            "name":    "SSL Certificate",
            "value":   "Check Failed",
            "explain": f"SSL check could not be completed: {str(e)[:120]}",
        }


def check_domain_age(hostname: str) -> dict:
    """Feature 4 – Domain age via WHOIS lookup."""
    try:
        info = whois.whois(hostname)
        creation = info.creation_date

        # python-whois may return a list
        if isinstance(creation, list):
            creation = creation[0]

        if not creation:
            return {
                "name":    "Domain Age",
                "value":   "Unknown",
                "explain": "WHOIS record exists but no creation date was found.",
            }

        now  = datetime.datetime.now(datetime.timezone.utc)
        if isinstance(creation, datetime.datetime):
            # Make both timezone-aware or both naive to allow subtraction
            if creation.tzinfo is None:
                now_naive = now.replace(tzinfo=None)
                age_days = (now_naive - creation).days
            else:
                age_days = (now - creation).days
        else:
            # Some registrars return date objects
            age_days = (now.date() - creation).days

        age_years = age_days / 365

        if age_days < 30:
            label   = f"{age_days} days old ⚠ (Very New)"
            explain = (
                "Domains registered very recently are a major phishing indicator. "
                "Attackers register domains specifically for short campaigns."
            )
        elif age_days < 180:
            label   = f"{age_days} days old (New)"
            explain = "Domain is relatively new. Exercise caution, especially with sensitive actions."
        else:
            label   = f"{age_days} days (~{age_years:.1f} years) ✓"
            explain = "Domain has existed for a substantial period, reducing the risk of it being a newly-created phishing site."

        return {"name": "Domain Age", "value": label, "explain": explain}

    except Exception as e:
        return {
            "name":    "Domain Age",
            "value":   "WHOIS Unavailable",
            "explain": f"Could not retrieve domain age: {str(e)[:120]}",
        }


def check_dns(hostname: str) -> dict:
    """Feature 5 – DNS resolution verification."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(hostname, "A")
        ips = [str(r) for r in answers]
        return {
            "name":    "DNS Resolution",
            "value":   f"Resolves → {', '.join(ips[:3])} ✓",
            "explain": "The domain resolves to a live IP address, confirming it is an active domain.",
        }
    except dns.resolver.NXDOMAIN:
        return {
            "name":    "DNS Resolution",
            "value":   "Domain Does Not Exist ✗",
            "explain": "DNS lookup returned NXDOMAIN – this domain does not exist.",
        }
    except dns.resolver.NoAnswer:
        return {
            "name":    "DNS Resolution",
            "value":   "No A Record Found",
            "explain": "The domain exists in DNS but has no A records (no server address).",
        }
    except Exception as e:
        return {
            "name":    "DNS Resolution",
            "value":   "DNS Check Failed",
            "explain": f"DNS resolution could not be completed: {str(e)[:120]}",
        }


def check_hosting_status(url: str) -> dict:
    """Feature 6 – HTTP reachability / hosting status."""
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (PhishingDetector/1.0)"},
        )
        code = resp.status_code
        if 200 <= code < 300:
            return {
                "name":    "Hosting Status",
                "value":   f"Online (HTTP {code}) ✓",
                "explain": "The website is live and returned a successful response.",
            }
        elif 300 <= code < 400:
            return {
                "name":    "Hosting Status",
                "value":   f"Redirects (HTTP {code})",
                "explain": "The server responded with a redirect. The final destination was followed.",
            }
        else:
            return {
                "name":    "Hosting Status",
                "value":   f"Error Response (HTTP {code}) ⚠",
                "explain": f"Server returned HTTP {code}. The site may be down or malfunctioning.",
            }
    except requests.exceptions.SSLError:
        return {
            "name":    "Hosting Status",
            "value":   "SSL Error ✗",
            "explain": "The HTTPS connection failed due to an SSL certificate error.",
        }
    except requests.exceptions.ConnectionError:
        return {
            "name":    "Hosting Status",
            "value":   "Offline / Unreachable ✗",
            "explain": "Could not connect to the website. It may be down or the domain is dead.",
        }
    except requests.exceptions.Timeout:
        return {
            "name":    "Hosting Status",
            "value":   "Timed Out ⚠",
            "explain": "The website did not respond within the timeout window.",
        }
    except Exception as e:
        return {
            "name":    "Hosting Status",
            "value":   "Check Failed",
            "explain": f"Could not determine hosting status: {str(e)[:120]}",
        }


def check_suspicious_keywords(url: str) -> dict:
    """Feature 7 – Suspicious keyword detection in the URL."""
    url_lower = url.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found:
        return {
            "name":    "Suspicious Keywords",
            "value":   f"Found: {', '.join(found)} ⚠",
            "explain": (
                f"The URL contains keyword(s) frequently used in phishing attacks: "
                f"{', '.join(found)}. Attackers use these to mimic legitimate services."
            ),
        }
    return {
        "name":    "Suspicious Keywords",
        "value":   "None Detected ✓",
        "explain": "No common phishing keywords were found in the URL.",
    }


def _calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


def check_url_structure(url: str, hostname: str) -> dict:
    """Feature 8 – Advanced URL structure anomaly analysis."""
    issues = []

    # IP address as hostname
    if is_ip_address(hostname):
        issues.append("IP address used instead of domain name")

    # Too many subdomains
    sub_count = count_subdomains(hostname)
    if sub_count > 3:
        issues.append(f"Excessive subdomains ({sub_count})")

    # Multiple hyphens (common in typosquatting / evasion)
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        issues.append(f"Multiple hyphens in domain ({hyphen_count})")

    # Excessive numbers in domain
    num_count = sum(c.isdigit() for c in hostname)
    if num_count >= 5:
        issues.append(f"Excessive numbers in domain ({num_count})")

    # High entropy (random character domains)
    domain_label = hostname.split(".")[0] if "." in hostname else hostname
    if _calculate_entropy(domain_label) > 3.8 and len(domain_label) > 8:
        issues.append("Random/gibberish domain name detected")

    # Suspicious TLDs
    suspicious_tlds = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".su"}
    for tld in suspicious_tlds:
        if hostname.endswith(tld):
            issues.append(f"Suspicious TLD ({tld})")
            break

    # Special / encoded characters tricks
    if "%" in url:
        issues.append("URL-encoded characters detected")
    if url.count("@") > 0:
        issues.append("Credential syntax (@) used to obfuscate domain")

    # Port in URL
    parsed = urlparse(url)
    if parsed.port and parsed.port not in (80, 443):
        issues.append(f"Non-standard port ({parsed.port})")

    # Punycode / IDN homograph
    if "xn--" in hostname:
        issues.append("Punycode / IDN domain (possible homograph attack)")

    # Double extension tricks
    if re.search(r'\.(exe|php|zip|js|html)\.(com|net|org|io)', hostname):
        issues.append("Double extension in hostname")

    if issues:
        return {
            "name":    "URL Structure",
            "value":   f"Suspicious Structure ⚠",
            "explain": "Multiple phishing naming patterns detected: " + "; ".join(issues) + ".",
            "issues":  issues,
        }
    return {
        "name":    "URL Structure",
        "value":   "Structure Looks Normal ✓",
        "explain": "No unusual structural patterns detected in the URL.",
        "issues":  [],
    }


# ─── Main Extractor ───────────────────────────────────────────────────────────

def extract_features(url: str) -> list:
    """
    Run all feature checks on the given URL.

    Returns a list of feature dicts:
      [{"name": ..., "value": ..., "explain": ...}, ...]

    This function NEVER raises – all exceptions are handled inside
    each sub-checker and returned as informative findings.
    """
    hostname = extract_hostname(url)

    features = [
        check_url_length(url),
        check_https(url),
        check_ssl_certificate(hostname),
        check_domain_age(hostname),
        check_dns(hostname),
        check_hosting_status(url),
        check_suspicious_keywords(url),
        check_url_structure(url, hostname),
    ]

    return features


# ─── Machine-Readable Signals (feeds Risk Engine) ────────────────────────────

def extract_raw_signals(url: str) -> tuple[list, dict]:
    """
    Run all feature checks and return BOTH:
      - findings : list[dict]  – human-readable, for the UI table
      - signals  : dict        – machine-readable, for the risk engine

    This is the preferred entry point when using the risk engine.
    It avoids running the same checks twice.

    Returns:
        (findings, signals)
    """
    from urllib.parse import urlparse as _urlparse

    hostname = extract_hostname(url)

    # ── Run all individual checks ──────────────────────────────────────────
    f_length   = check_url_length(url)
    f_https    = check_https(url)
    f_ssl      = check_ssl_certificate(hostname)
    f_age      = check_domain_age(hostname)
    f_dns      = check_dns(hostname)
    f_host     = check_hosting_status(url)
    f_keywords = check_suspicious_keywords(url)
    f_struct   = check_url_structure(url, hostname)

    findings = [f_length, f_https, f_ssl, f_age, f_dns, f_host, f_keywords, f_struct]

    # ── Derive machine-readable signals ────────────────────────────────────
    parsed = _urlparse(url)

    # Protocol
    is_https = parsed.scheme.lower() == "https"

    # SSL status
    ssl_val   = f_ssl.get("value", "")
    ssl_valid   = "✓" in ssl_val and "Expired" not in ssl_val
    ssl_expired = "Expired" in ssl_val
    ssl_invalid = "Invalid" in ssl_val or "Untrusted" in ssl_val

    # Domain age
    age_val = f_age.get("value", "")
    domain_age_days: int | None = None
    if "days" in age_val:
        import re as _re
        m = _re.search(r"(\d+)\s+day", age_val)
        if m:
            domain_age_days = int(m.group(1))

    # Keywords
    kw_val = f_keywords.get("value", "")
    has_keywords = "Found:" in kw_val
    keyword_list: list[str] = []
    if has_keywords:
        # extract "Found: login, verify → ..." pattern
        import re as _re2
        m2 = _re2.search(r"Found:\s*([^⚠]+)", kw_val)
        if m2:
            keyword_list = [k.strip() for k in m2.group(1).split(",") if k.strip()]

    # DNS
    dns_val    = f_dns.get("value", "")
    dns_resolves = "✓" in dns_val

    # Signals dict
    signals = {
        "is_https":            is_https,
        "ssl_valid":           ssl_valid,
        "ssl_expired":         ssl_expired,
        "ssl_invalid":         ssl_invalid,
        "domain_age_days":     domain_age_days,
        "has_suspicious_keywords": has_keywords,
        "keyword_list":        keyword_list,
        "is_ip_host":          is_ip_address(hostname),
        "subdomain_count":     count_subdomains(hostname),
        "url_length":          len(url),
        "has_special_chars":   has_special_characters(url),
        "dns_resolves":        dns_resolves,
        "is_online":           "✓" in f_host.get("value", ""),
        "structural_issues":   f_struct.get("issues", []),
    }

    return findings, signals

