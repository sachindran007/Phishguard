# PhishGuard – Real-Time Phishing URL Detector

A production-ready full-stack web application that detects phishing URLs in real time using **Python Flask**, **React + Vite**, and **Google Gemini AI**.

---

## 📸 Project Overview

PhishGuard analyzes any URL across **8 security dimensions** and returns an AI-powered threat verdict in seconds — with zero database dependencies.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔬 **8-Layer Security Analysis** | URL length, HTTPS, SSL, WHOIS domain age, DNS, hosting status, keyword detection, structure analysis |
| 🤖 **Gemini AI Verdict** | Classified as: *Looks Safe / Suspicious / High Risk / Phishing Detected* |
| ⚡ **Real-Time** | Stateless architecture – every scan is independent |
| 🛡️ **Resilient** | Never crashes on bad URLs, offline sites, WHOIS failures, or SSL errors |
| 🎨 **Dark UI** | Cybersecurity-themed glassmorphism design with micro-animations |
| 🔒 **Secure** | API key stored server-side only; never exposed to the frontend |

---

## 🏗️ Tech Stack

### Backend
- **Python 3.11+** · **Flask 3** · **Flask-CORS**
- **google-generativeai** (Gemini 1.5 Flash)
- **python-whois** · **dnspython** · **tldextract** · **requests**
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
│   ├── app.py                  ← Flask API entry point
│   ├── requirements.txt
│   ├── .env                    ← Local secrets (git-ignored)
│   ├── .env.template           ← Template for .env
│   │
│   ├── services/
│   │   ├── url_utils.py        ← URL normalization & validation
│   │   ├── feature_extractor.py← 8 security feature analyzers
│   │   └── ai_analyzer.py      ← Gemini AI integration
│   │
│   └── tests/
│       └── test_api.py         ← pytest test suite
│
└── frontend/
    ├── package.json
    ├── index.html
    ├── vite.config.js          ← Proxy /api → localhost:5000
    │
    └── src/
        ├── main.jsx
        ├── App.jsx             ← State management & flow
        ├── App.css             ← Full design system
        │
        └── components/
            ├── UrlInputForm.jsx
            ├── VerdictBanner.jsx
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

### 1. Clone / Navigate to the project

```bash
cd phishing_detect
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
```

#### Configure Environment Variables

```bash
# Copy the template
cp .env.template .env
```

Edit `.env` and add your real Gemini API key:

```env
GEMINI_API_KEY=AIzaSy...your_actual_key_here
```

#### Start the Flask server

```bash
flask run
# → Running on http://localhost:5000
```

---

### 3. Frontend Setup

Open a **new terminal window**:

```bash
cd frontend

# Install Node packages
npm install

# Start the Vite dev server
npm run dev
# → Running on http://localhost:5173
```

Open **http://localhost:5173** in your browser. 🎉

---

## 🔑 Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | ✅ Yes | Your Google Gemini API key |
| `FLASK_ENV` | Optional | `development` or `production` |
| `FLASK_DEBUG` | Optional | `1` to enable debug mode |

> **Security**: The API key is loaded server-side via `python-dotenv`. It is **never** sent to the browser.

---

## 📡 API Documentation

### `POST /api/analyze`

Analyze a URL for phishing indicators.

**Request**

```http
POST /api/analyze
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Success Response** `200 OK`

```json
{
  "ai_result": {
    "verdict": "Looks Safe",
    "reason": "The domain is well-established with a valid SSL certificate and no suspicious patterns."
  },
  "findings": [
    {
      "name": "URL Length",
      "value": "19 characters (Normal)",
      "explain": "The URL is a typical length. Shorter URLs are generally less suspicious."
    },
    {
      "name": "Protocol",
      "value": "HTTPS ✓",
      "explain": "The site uses HTTPS, meaning traffic is encrypted in transit."
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Error Response** `400 Bad Request`

```json
{
  "error": "The 'url' field is required and cannot be empty."
}
```

**Verdict Values**

| Verdict | Meaning |
|---|---|
| `Looks Safe` | No significant red flags |
| `Suspicious` | Some concerning indicators |
| `High Risk` | Multiple strong phishing signals |
| `Phishing Detected` | Clear phishing site |

---

### `GET /api/health`

Liveness check.

```json
{ "status": "ok", "timestamp": "2024-01-15T10:30:00Z" }
```

---

## 🧪 Running Tests

```bash
cd backend
pytest tests/ -v
```

Tests cover: health endpoint, input validation, valid URL responses, response structure, verdict categories, and edge cases.

---

## 🔒 Security Notes

- The Gemini API key is **only** accessible server-side via environment variables.
- User-supplied URLs are validated before any network request is made.
- All external calls (WHOIS, DNS, HTTP) use timeouts to prevent hanging.
- The application never crashes — all exceptions return structured JSON errors.

---

## 📄 License

MIT License – see [LICENSE](LICENSE) for details.
