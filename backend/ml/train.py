"""
train.py
--------
Train a Random Forest phishing detection model on URL features.

Run ONCE from the backend/ directory to generate ml/model.pkl:

    python -m ml.train

The training dataset is synthetically generated from real-world phishing
patterns — no external dataset download required. For production use,
replace SAMPLES with a real labeled dataset (e.g. UCI Phishing Dataset).

Features used (must match detector.py):
  0  url_length          – total URL character count
  1  num_dots            – number of dots in hostname
  2  num_hyphens         – number of hyphens in full URL
  3  num_slashes         – number of slashes after scheme
  4  num_special_chars   – count of @, %, = chars
  5  has_https           – 1 if HTTPS else 0
  6  domain_age_days     – days since registration (999 = unknown)
  7  subdomain_count     – number of subdomains
  8  is_ip_host          – 1 if hostname is an IP
  9  keyword_count       – number of suspicious keywords found
  10 has_at_sign         – 1 if @ in URL
  11 url_depth           – number of path segments
"""

import os
import sys
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# ─── Synthetic Training Data ──────────────────────────────────────────────────
# Format: [url_len, dots, hyphens, slashes, specials, https, age_days,
#          subdomains, is_ip, keywords, at_sign, depth]
# Label:   0 = legitimate, 1 = phishing

rng = np.random.default_rng(42)

def _legit(n: int) -> np.ndarray:
    """Generate n legitimate URL feature vectors."""
    return np.column_stack([
        rng.integers(15, 60,  n),       # url_length (short-medium)
        rng.integers(1,  3,   n),       # num_dots
        rng.integers(0,  2,   n),       # num_hyphens
        rng.integers(1,  4,   n),       # num_slashes
        rng.integers(0,  1,   n),       # num_special_chars
        np.ones(n),                      # has_https (almost always)
        rng.integers(365, 7000, n),     # domain_age_days (old domains)
        rng.integers(0,  2,   n),       # subdomain_count
        np.zeros(n),                     # is_ip_host
        np.zeros(n),                     # keyword_count
        np.zeros(n),                     # has_at_sign
        rng.integers(0,  3,   n),       # url_depth
    ])

def _phish(n: int) -> np.ndarray:
    """Generate n phishing URL feature vectors."""
    return np.column_stack([
        rng.integers(60, 200,  n),      # url_length (long)
        rng.integers(3,  8,    n),      # num_dots (many subdomains)
        rng.integers(2,  6,    n),      # num_hyphens
        rng.integers(3,  8,    n),      # num_slashes
        rng.integers(1,  5,    n),      # num_special_chars
        rng.integers(0,  2,    n),      # has_https (often HTTP)
        rng.integers(0,  90,   n),      # domain_age_days (new!)
        rng.integers(3,  7,    n),      # subdomain_count (many)
        rng.integers(0,  2,    n),      # is_ip_host
        rng.integers(1,  5,    n),      # keyword_count (suspicious words)
        rng.integers(0,  2,    n),      # has_at_sign
        rng.integers(3,  8,    n),      # url_depth
    ])

N = 5000  # samples per class

X_legit = _legit(N)
X_phish = _phish(N)
X = np.vstack([X_legit, X_phish]).astype(float)
y = np.array([0] * N + [1] * N)

# ─── Train ────────────────────────────────────────────────────────────────────

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    min_samples_leaf=4,
    random_state=42,
    n_jobs=-1,
)
model.fit(X_train, y_train)

print("\n-- Training complete ----------------------------------------")
print(classification_report(y_test, model.predict(X_test),
                             target_names=["Legitimate", "Phishing"]))

# ─── Save ─────────────────────────────────────────────────────────────────────

out_path = os.path.join(os.path.dirname(__file__), "model.pkl")
joblib.dump(model, out_path)
print(f"Model saved -> {out_path}")
