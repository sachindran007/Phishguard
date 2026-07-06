"""
Accuracy Measurement Framework
------------------------------
This script tests the PhishGuard pipeline against a local dataset
of known safe and phishing URLs, measuring accuracy, FP, FN, and speed.
"""

import os
import time
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

API_URL = "http://localhost:5000/api/analyze"
DATASET_DIR = os.path.join(os.path.dirname(__file__), "tests", "datasets")

def load_urls(filename: str) -> list[str]:
    path = os.path.join(DATASET_DIR, filename)
    if not os.path.exists(path):
        print(f"Warning: Dataset {path} not found.")
        return []
    with open(path, "r", encoding="utf-8") as f:
        # Ignore empty lines and comments
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def scan_url(url: str, expected_is_phishing: bool) -> dict:
    """Sends the URL to the local API and returns the result."""
    start_time = time.time()
    try:
        # Turn off visual scanning for bulk tests to avoid opening 20 browsers
        resp = requests.post(API_URL, json={"url": url, "visual": False}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        
        # Consider "High Risk" and "Phishing Detected" as phishing
        is_phishing = data.get("risk_score", 0) >= 61
        
        return {
            "url": url,
            "success": True,
            "expected_is_phishing": expected_is_phishing,
            "predicted_is_phishing": is_phishing,
            "risk_score": data.get("risk_score", 0),
            "verdict": data.get("verdict", "Unknown"),
            "time": time.time() - start_time
        }
    except Exception as e:
        return {
            "url": url,
            "success": False,
            "error": str(e),
            "time": time.time() - start_time
        }

def run_tests():
    safe_urls = load_urls("safe_urls.txt")
    phishing_urls = load_urls("phishing_urls.txt")

    if not safe_urls and not phishing_urls:
        print("No URLs to test. Please add URLs to the datasets directory.")
        return

    print(f"Loaded {len(safe_urls)} safe URLs and {len(phishing_urls)} phishing URLs.")
    print("Connecting to local API (ensure Flask is running)...")
    
    tasks = []
    # Mix them together
    for u in safe_urls:
        tasks.append((u, False))
    for u in phishing_urls:
        tasks.append((u, True))

    results = []
    
    # Run requests concurrently to save time, but not too many to overwhelm local server
    with ThreadPoolExecutor(max_workers=5) as pool:
        future_to_url = {pool.submit(scan_url, u, expected): u for u, expected in tasks}
        for i, future in enumerate(as_completed(future_to_url)):
            res = future.result()
            results.append(res)
            print(f"[{i+1}/{len(tasks)}] Scanned {res['url'][:40]}... -> {res.get('verdict', 'Failed')}")

    # Calculate metrics
    total = len(results)
    successful = [r for r in results if r["success"]]
    failed = total - len(successful)
    
    if not successful:
        print("All requests failed. Is the API running?")
        return

    true_positives = 0
    true_negatives = 0
    false_positives = 0
    false_negatives = 0
    total_time = sum(r["time"] for r in successful)

    for r in successful:
        if r["expected_is_phishing"] and r["predicted_is_phishing"]:
            true_positives += 1
        elif not r["expected_is_phishing"] and not r["predicted_is_phishing"]:
            true_negatives += 1
        elif not r["expected_is_phishing"] and r["predicted_is_phishing"]:
            false_positives += 1
        elif r["expected_is_phishing"] and not r["predicted_is_phishing"]:
            false_negatives += 1

    accuracy = (true_positives + true_negatives) / len(successful) * 100
    fp_rate = (false_positives / len(successful)) * 100
    fn_rate = (false_negatives / len(successful)) * 100
    avg_time = total_time / len(successful)

    print("\n==================================================")
    print("TEST RESULTS")
    print("==================================================")
    print(f"Total URLs Tested: {total}")
    if failed > 0:
        print(f"Failed Requests: {failed}")
    print(f"Average Scan Time: {avg_time:.2f} seconds")
    print(f"Accuracy: {accuracy:.1f}%")
    print(f"False Positives: {fp_rate:.1f}% ({false_positives} URLs)")
    print(f"False Negatives: {fn_rate:.1f}% ({false_negatives} URLs)")
    print("==================================================\n")

if __name__ == "__main__":
    run_tests()
