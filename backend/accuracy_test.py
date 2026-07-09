"""
accuracy_test.py
----------------
Detection accuracy benchmarking for PhishGuard.

Runs the brand detector and feature extractor against test datasets
and generates precision/recall/F1 metrics.

Usage:
    cd backend
    python accuracy_test.py

Outputs:
    reports/accuracy_report.json
    reports/accuracy_report.md
"""

import os
import sys
import json
import time
import datetime

# Ensure backend root is on path
sys.path.insert(0, os.path.dirname(__file__))

from services.brand_detector import check_brand_impersonation, is_official_domain
from services.feature_extractor import check_url_structure
from services.url_utils import extract_hostname


# ─── Config ───────────────────────────────────────────────────────────────────

DATASETS_DIR = os.path.join(os.path.dirname(__file__), "tests", "datasets")
REPORTS_DIR  = os.path.join(os.path.dirname(__file__), "reports")


def _load_urls(filename: str) -> list[str]:
    """Load URLs from a dataset file (one per line, skip blanks/comments)."""
    path = os.path.join(DATASETS_DIR, filename)
    if not os.path.exists(path):
        print(f"  ⚠ Dataset not found: {path}")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _analyze_url(url: str) -> dict:
    """Run brand detection + structure analysis on a single URL."""
    hostname = extract_hostname(url)
    start = time.time()
    brand_result = check_brand_impersonation(url, hostname)
    struct_result = check_url_structure(url, hostname)
    elapsed = time.time() - start

    is_threat = (
        brand_result.get("brand_impersonation", False)
        or struct_result.get("structure_status") == "Suspicious"
    )

    return {
        "url": url,
        "predicted_threat": is_threat,
        "brand_detected": brand_result.get("brand_impersonation", False),
        "target_brand": brand_result.get("target_brand"),
        "similarity": brand_result.get("similarity", 0),
        "method": brand_result.get("method"),
        "structure_status": struct_result.get("structure_status", "Normal"),
        "detected_patterns": struct_result.get("detected_patterns", []),
        "scan_time_ms": round(elapsed * 1000, 2),
    }


def _compute_metrics(
    tp: int, fp: int, tn: int, fn: int
) -> dict:
    """Compute accuracy, precision, recall, F1."""
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total * 100 if total else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    return {
        "total": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "accuracy": round(accuracy, 2),
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "f1_score": round(f1, 2),
    }


def run_benchmark():
    """Run full accuracy benchmark against all datasets."""
    print("=" * 60)
    print("  PhishGuard — Detection Accuracy Benchmark")
    print("=" * 60)

    # Load datasets
    safe_urls = _load_urls("safe_urls.txt")
    phishing_urls = _load_urls("phishing_urls.txt")
    typo_urls = _load_urls("typosquatting_urls.txt")
    banking_urls = _load_urls("banking_phishing_urls.txt")
    homoglyph_urls = _load_urls("homoglyph_urls.txt")

    all_malicious = phishing_urls + typo_urls + banking_urls + homoglyph_urls

    print(f"\n  Safe URLs:       {len(safe_urls)}")
    print(f"  Phishing URLs:   {len(phishing_urls)}")
    print(f"  Typosquatting:   {len(typo_urls)}")
    print(f"  Banking:         {len(banking_urls)}")
    print(f"  Homoglyph:       {len(homoglyph_urls)}")
    print(f"  Total:           {len(safe_urls) + len(all_malicious)}")
    print()

    tp = fp = tn = fn = 0
    total_time = 0
    results = []

    # Test safe URLs (expected: NOT threat)
    print("  Testing safe URLs...")
    for url in safe_urls:
        r = _analyze_url(url)
        total_time += r["scan_time_ms"]
        results.append({**r, "expected": "safe"})
        if r["predicted_threat"]:
            fp += 1
            print(f"    ✗ FALSE POSITIVE: {url}")
        else:
            tn += 1

    # Test malicious URLs (expected: threat)
    print("  Testing malicious URLs...")
    for url in all_malicious:
        r = _analyze_url(url)
        total_time += r["scan_time_ms"]
        results.append({**r, "expected": "malicious"})
        if r["predicted_threat"]:
            tp += 1
        else:
            fn += 1
            print(f"    ✗ FALSE NEGATIVE: {url}")

    # Compute metrics
    metrics = _compute_metrics(tp, fp, tn, fn)
    avg_time = total_time / len(results) if results else 0

    report = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "datasets": {
            "safe_urls": len(safe_urls),
            "phishing_urls": len(phishing_urls),
            "typosquatting_urls": len(typo_urls),
            "banking_phishing_urls": len(banking_urls),
            "homoglyph_urls": len(homoglyph_urls),
        },
        "metrics": metrics,
        "average_scan_time_ms": round(avg_time, 2),
        "total_scan_time_ms": round(total_time, 2),
        "false_positives": [r for r in results if r["expected"] == "safe" and r["predicted_threat"]],
        "false_negatives": [r for r in results if r["expected"] == "malicious" and not r["predicted_threat"]],
    }

    # Save reports
    os.makedirs(REPORTS_DIR, exist_ok=True)

    json_path = os.path.join(REPORTS_DIR, "accuracy_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    md_path = os.path.join(REPORTS_DIR, "accuracy_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# PhishGuard — Detection Accuracy Report\n\n")
        f.write(f"**Generated:** {report['timestamp']}\n\n")
        f.write("## Dataset Summary\n\n")
        f.write("| Dataset | Count |\n|---------|-------|\n")
        for ds, count in report["datasets"].items():
            f.write(f"| {ds} | {count} |\n")
        f.write(f"| **Total** | **{metrics['total']}** |\n\n")
        f.write("## Metrics\n\n")
        f.write("| Metric | Value |\n|--------|-------|\n")
        f.write(f"| Accuracy | {metrics['accuracy']}% |\n")
        f.write(f"| Precision | {metrics['precision']}% |\n")
        f.write(f"| Recall | {metrics['recall']}% |\n")
        f.write(f"| F1 Score | {metrics['f1_score']}% |\n")
        f.write(f"| True Positives | {metrics['true_positives']} |\n")
        f.write(f"| False Positives | {metrics['false_positives']} |\n")
        f.write(f"| True Negatives | {metrics['true_negatives']} |\n")
        f.write(f"| False Negatives | {metrics['false_negatives']} |\n")
        f.write(f"| Avg Scan Time | {report['average_scan_time_ms']:.2f} ms |\n\n")

        if report["false_positives"]:
            f.write("## False Positives\n\n")
            for fp_item in report["false_positives"]:
                f.write(f"- `{fp_item['url']}` → detected as threat\n")
            f.write("\n")

        if report["false_negatives"]:
            f.write("## False Negatives\n\n")
            for fn_item in report["false_negatives"]:
                f.write(f"- `{fn_item['url']}` → missed (structure: {fn_item['structure_status']})\n")
            f.write("\n")

    # Print summary
    print()
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    print(f"  Total URLs:       {metrics['total']}")
    print(f"  Accuracy:         {metrics['accuracy']}%")
    print(f"  Precision:        {metrics['precision']}%")
    print(f"  Recall:           {metrics['recall']}%")
    print(f"  F1 Score:         {metrics['f1_score']}%")
    print(f"  False Positives:  {metrics['false_positives']}")
    print(f"  False Negatives:  {metrics['false_negatives']}")
    print(f"  Avg Scan Time:    {avg_time:.2f} ms")
    print()
    print(f"  Reports saved to: {REPORTS_DIR}/")
    print("=" * 60)

    return report


if __name__ == "__main__":
    run_benchmark()
