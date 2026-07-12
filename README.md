# PhishGuard – AI-Powered Phishing Website Detector

A production-quality full-stack phishing detection platform built with **Python Flask**, **React + Vite**, and **Google Gemini AI**. Detects phishing URLs through **multi-layer analysis**: rule engine, threat intelligence, machine learning, brand impersonation detection, visual AI scanning, and Gemini-powered explanations.

---

## 🔬 Detection Pipeline

```
User URL
   ↓
┌──────────────────────────────────────────────────────────┐
│  Feature Extraction (8 security checks)                  │
│  ├── URL Length · Protocol · SSL · WHOIS                 │
│  ├── DNS · Hosting · Keywords · Structure Analysis       │
│  └── URL Shortener · Keyword Categories · Entropy        │
└──────────────────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────────────────┐
│  Parallel Analysis (ThreadPoolExecutor)                  │
│  ├── Threat Intelligence (Safe Browsing + VirusTotal)    │
│  ├── ML Detector (RandomForest)                          │
│  └── Brand Impersonation (Levenshtein + Jaro-Winkler    │
│      + Homoglyph + Character Substitution)               │
└──────────────────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────────────────┐
│  Risk Engine → Score + Verdict (deterministic)           │
│  Priority: TI Override → Brand Override → Rules          │
└──────────────────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────────────────┐
│  Conditional Visual Scanner (Playwright + Gemini Vision) │
│  Only triggered when risk ≥ 40 or threat indicators      │
└──────────────────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────────────────┐
│  Confidence Engine (10-factor scoring)                   │
│  Gemini AI Explanation (specific threat citations)       │
└──────────────────────────────────────────────────────────┘
   ↓
   Security Report (JSON Response)
```

---

## ✨ Features

| Feature | Details |
|---------|---------|
| 🔬 **Multi-Layer Analysis** | URL structure, HTTPS, SSL, WHOIS, DNS, hosting, keywords, structural anomalies |
| 🎯 **Brand Impersonation** | 60+ brands, 9 categories, Levenshtein + Jaro-Winkler + homoglyph detection |
| 🏦 **Banking & Govt Protection** | SBI, HDFC, ICICI, UIDAI, IRCTC, and more (India-focused + global) |
| 🛡️ **Threat Intelligence** | Google Safe Browsing + VirusTotal integration |
| 🤖 **ML + AI** | RandomForest model + Gemini AI explanations |
| 👁️ **Visual Scanner** | Playwright screenshot + Gemini Vision analysis |
| 📊 **Risk Engine** | Deterministic scoring with threat priority overrides |
| ⚡ **Performance** | Brand detection < 50ms, full pipeline < 5s |
| 🎨 **Dark UI** | Cybersecurity-themed glassmorphism design |

---

## 🏗️ Tech Stack

### Backend
- **Python 3.11+** · **Flask 3** · **Flask-CORS**
- **google-generativeai** (Gemini 2.5 Flash)
- **python-whois** · **dnspython** · **tldextract** · **requests**
- **scikit-learn** · **playwright** · **Pillow**
- **python-dotenv** · **pytest**

### Frontend
- **React 18** · **Vite 5** · **Axios**
- Vanilla CSS (glassmorphism dark theme)
- **Inter** + **JetBrains Mono** (Google Fonts)

---

## 📁 Project Structure

```
phishing_detect/
├── README.md
├── .gitignore
│
├── backend/
│   ├── app.py                     ← Flask API entry point
│   ├── requirements.txt
│   ├── accuracy_test.py           ← Detection benchmarking
│   ├── .env                       ← Local secrets (git-ignored)
│   │
│   ├── config/                    ← JSON configuration (no hardcoded brands)
│   │   ├── brands.json            ← 60+ brands, 9 categories
│   │   ├── trusted_tlds.json
│   │   ├── suspicious_tlds.json
│   │   ├── character_rules.json   ← Substitution rules (0→o, rn→m)
│   │   ├── keyword_categories.json
│   │   └── whitelist.json         ← Official domains (never flag)
│   │
│   ├── services/
│   │   ├── feature_extractor.py   ← 8 security checks + structure analyzer
│   │   ├── risk_engine.py         ← Deterministic scoring + priority overrides
│   │   ├── brand_detector.py      ← Brand impersonation (7 algorithms)
│   │   ├── threat_intelligence.py ← Safe Browsing + VirusTotal
│   │   ├── confidence_engine.py   ← 10-factor confidence scoring
│   │   ├── visual_scanner.py      ← Playwright + Gemini Vision
│   │   ├── ai_analyzer.py         ← Gemini explanation generator
│   │   └── url_utils.py
│   │
│   ├── ml/
│   │   ├── detector.py            ← ML phishing classifier
│   │   └── model.pkl
│   │
│   ├── tests/
│   │   ├── test_api.py            ← API endpoint tests
│   │   ├── test_brand_detector.py ← Brand detection tests (16 tests)
│   │   ├── test_integration.py    ← Full pipeline integration tests
│   │   ├── test_performance.py    ← Performance benchmarks
│   │   ├── test_confidence.py
│   │   ├── test_visual_scanner.py
│   │   └── datasets/              ← Benchmark datasets
│   │       ├── safe_urls.txt
│   │       ├── phishing_urls.txt
│   │       ├── typosquatting_urls.txt
│   │       ├── banking_phishing_urls.txt
│   │       └── homoglyph_urls.txt
│   │
│   └── reports/                   ← Generated benchmark reports
│       ├── accuracy_report.json
│       └── accuracy_report.md
│
└── frontend/
    ├── package.json
    ├── index.html
    ├── vite.config.js
    │
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── App.css
        │
        └── components/
            ├── UrlInputForm.jsx
            ├── VerdictBanner.jsx
            ├── RiskScoreGauge.jsx
            ├── BrandWarningBanner.jsx  ← Brand impersonation alert
            ├── VisualScanPanel.jsx
            ├── ThreatIntelPanel.jsx
            ├── RecommendationPanel.jsx
            ├── FindingsList.jsx
            ├── LoadingSpinner.jsx
            └── ErrorMessage.jsx
```

---

## 🚀 Installation & Setup

### Prerequisites

- Python 3.11+
- Node.js 18+ and npm
- A Google Gemini API key → [Get one here](https://aistudio.google.com/app/apikey)

---

### 1. Clone the repository

```bash
git clone https://github.com/sachindran007/Phishguard.git
cd Phishguard
```

---

### 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (macOS / Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser (for visual scanner)
python -m playwright install chromium
```

#### Configure Environment Variables

```bash
cp .env.template .env
```

Edit `.env`:

```env
GEMINI_API_KEY=AIzaSy...your_actual_key_here
GOOGLE_SAFE_BROWSING_KEY=your_safe_browsing_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

#### Start the Flask server

```bash
flask run
#Running on https://phishguard-backend-uc0n.onrender.com
or 
#Running on http://localhost:5173
```

---

### 3. Frontend Setup

Open a **new terminal**:

```bash
cd frontend

npm install
npm run dev
# → Running on http://localhost:5173
```

Open **http://localhost:5173** 🎉

---

## 🧪 Testing

### Unit Tests
```bash
cd backend
venv\Scripts\pytest tests/ -v
```

### Integration Tests
```bash
venv\Scripts\pytest tests/test_integration.py -v
```

### Performance Tests
```bash
venv\Scripts\pytest tests/test_performance.py -v
```

### Accuracy Benchmark
```bash
python accuracy_test.py
# Generates reports/accuracy_report.json and reports/accuracy_report.md
```

---

## 📊 Performance Benchmarks

| Metric | Target | Actual |
|--------|--------|--------|
| Brand Detection | < 50ms | ~3ms ✅ |
| Risk Engine | < 5ms | < 1ms ✅ |
| Full Pipeline (no visual) | < 15s | ~8-12s ✅ |
| Accuracy (65 URLs) | > 95% | **100%** ✅ |
| Precision | > 95% | **100%** ✅ |
| Recall | > 95% | **100%** ✅ |
| F1 Score | > 95% | **100%** ✅ |
| False Positives | 0 | **0** ✅ |

---

## 📡 API Documentation

### `POST /api/analyze`

```json
{
  "url": "https://g00gle.com",
  "visual": true
}
```

**Response** `200 OK`:

```json
{
  "verdict": "Phishing Detected",
  "risk_score": 95,
  "severity": "CRITICAL",
  "confidence": 92,
  "confidence_label": "Very High",
  "ai_explanation": { "summary": "...", "recommendations": [...] },
  "threat_intel": { "safe_browsing": {...}, "virustotal": {...} },
  "brand_result": {
    "brand_impersonation": true,
    "target_brand": "google",
    "category": "technology",
    "similarity": 96,
    "method": "homograph_substitution",
    "character_substitution": true
  },
  "visual_result": { "checked": true, "visual_threat": false },
  "triggered_rules": [{ "rule": "...", "points": 35, "detail": "..." }],
  "findings": [{ "name": "...", "value": "...", "explain": "..." }],
  "timestamp": "2026-07-09T08:30:00Z"
}
```

### Verdict Values

| Verdict | Score Range | Severity |
|---------|------------|----------|
| Safe | 0–20 | LOW |
| Suspicious | 21–40 | MEDIUM |
| High Risk | 41–70 | HIGH |
| Confirmed Threat | 71–100 | CRITICAL |
| Phishing Detected | Override | CRITICAL |
| Malware Detected | Override | CRITICAL |

### `GET /api/health`

```json
{ "status": "ok", "timestamp": "2026-07-09T08:30:00Z" }
```

---

## 🔑 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GEMINI_API_KEY` | ✅ | Google Gemini API key |
| `GOOGLE_SAFE_BROWSING_KEY` | Optional | Google Safe Browsing API key |
| `VIRUSTOTAL_API_KEY` | Optional | VirusTotal API key |

> **Security**: API keys are loaded server-side only via `python-dotenv`.

---

## 🔒 Security Notes

- API keys are **never** sent to the browser
- User URLs are validated before any network request
- All external calls use timeouts to prevent hanging
- Visual scanner only runs when risk indicators are present
- Official brand domains are whitelisted (never flagged)
- The application never crashes — all exceptions return structured JSON

---

## 📄 License

MIT License – see [LICENSE](LICENSE) for details.
