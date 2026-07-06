/**
 * App.jsx  (v2)
 * -------------
 * Root component — PhishGuard v2.
 *
 * New state fields: risk_score, severity, triggered_rules,
 *                   ai_explanation, threat_intel, ml_result
 * New components:   RiskScoreGauge, ThreatIntelPanel, RecommendationPanel
 */

import { useState } from 'react'
import axios from 'axios'

import UrlInputForm        from './components/UrlInputForm.jsx'
import LoadingSpinner      from './components/LoadingSpinner.jsx'
import VerdictBanner       from './components/VerdictBanner.jsx'
import FindingsList        from './components/FindingsList.jsx'
import ErrorMessage        from './components/ErrorMessage.jsx'
import RiskScoreGauge      from './components/RiskScoreGauge.jsx'
import ThreatIntelPanel    from './components/ThreatIntelPanel.jsx'
import RecommendationPanel from './components/RecommendationPanel.jsx'
import BrandWarningBanner  from './components/BrandWarningBanner.jsx'
import VisualScanPanel     from './components/VisualScanPanel.jsx'

const API_ENDPOINT = '/api/analyze'

const STAT_PILLS = [
  { icon: '🔬', label: '11 Security Checks' },
  { icon: '🛡️', label: 'Threat Intel',   value: 'VirusTotal' },
  { icon: '🤖', label: 'ML + AI',         value: 'Powered'   },
  { icon: '⚡', label: 'Real-Time'                            },
]

function extractErrorMessage(err) {
  if (err.response) {
    const d = err.response.data
    return d?.error ?? `Server error: HTTP ${err.response.status}`
  }
  if (err.request) {
    return 'Could not reach the backend server. Make sure Flask is running on port 5000.'
  }
  return err.message || 'An unexpected error occurred.'
}

export default function App() {
  const [url,            setUrl]            = useState('')
  const [loading,        setLoading]        = useState(false)
  const [error,          setError]          = useState(null)
  const [analysisResult, setAnalysisResult] = useState(null)

  async function handleAnalyze() {
    if (!url.trim()) return
    setError(null)
    setAnalysisResult(null)
    setLoading(true)
    try {
      const { data } = await axios.post(
        API_ENDPOINT,
        { url: url.trim() },
        { timeout: 90_000 }
      )
      setAnalysisResult(data)
    } catch (err) {
      setError(extractErrorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  const r = analysisResult

  return (
    <div className="app">
      {/* ── Header ── */}
      <header className="app-header" role="banner">
        <div className="header-badge">AI + ML Security Platform</div>
        <h1 className="app-title">
          PhishGuard
          <span>URL Threat Analyzer</span>
        </h1>
        <p className="app-subtitle">
          Multi-layer phishing detection: Rule Engine · Threat Intelligence · Machine Learning · Gemini AI
        </p>
      </header>

      {/* ── Stat Pills ── */}
      <div className="stat-pills" aria-hidden="true">
        {STAT_PILLS.map(pill => (
          <div key={pill.label} className="stat-pill">
            <span className="stat-pill__icon">{pill.icon}</span>
            {pill.value && <span className="stat-pill__value">{pill.value}</span>}
            <span>{pill.label}</span>
          </div>
        ))}
      </div>

      {/* ── Main ── */}
      <main className="app-main" role="main">
        <UrlInputForm
          url={url}
          onUrlChange={setUrl}
          onSubmit={handleAnalyze}
          loading={loading}
        />

        {error   && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
        {loading && <LoadingSpinner />}

        {r && !loading && (
          <>
            {/* ── Brand Impersonation Warning (Critical Top Level) ── */}
            <BrandWarningBanner brandResult={r.brand_result} />

            {/* ── Score + Verdict row ── */}
            <div className="results-hero">
              <RiskScoreGauge
                score={r.risk_score ?? 0}
                verdict={r.verdict ?? r.ai_result?.verdict}
                confidence={r.confidence}
              />
              <div className="results-hero__banner">
                <VerdictBanner
                  verdict={r.verdict}
                  score={r.risk_score}
                  aiResult={r.ai_result}
                  timestamp={r.timestamp}
                />
              </div>
            </div>

            {/* ── AI Explanation + Recommendations ── */}
            <RecommendationPanel
              aiExplanation={r.ai_explanation}
              mlResult={r.ml_result}
            />

            {/* ── Threat Intelligence & Visual Scan ── */}
            <ThreatIntelPanel threatIntel={r.threat_intel} />
            <VisualScanPanel visualResult={r.visual_result} />

            {/* ── Technical Findings ── */}
            <FindingsList findings={r.findings} />
          </>
        )}
      </main>

      {/* ── Footer ── */}
      <footer className="app-footer" role="contentinfo">
        <p>
          PhishGuard v2 &middot; Rule Engine + Threat Intel + ML + Gemini AI &middot;{' '}
          <a href="https://aistudio.google.com" target="_blank" rel="noopener noreferrer">
            Google Gemini
          </a>
        </p>
      </footer>
    </div>
  )
}
