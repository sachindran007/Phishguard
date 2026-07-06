/**
 * VerdictBanner.jsx  (v2)
 * -----------------------
 * Displays the verdict, risk score/100, reason, and scan timestamp.
 * Now receives both score and aiResult for rich display.
 *
 * Props:
 *   verdict    string   – "Looks Safe" | "Suspicious" | "High Risk" | "Phishing Detected"
 *   score      number   – 0–100
 *   aiResult   { verdict, reason }  (legacy compat)
 *   timestamp  string
 */

const VERDICT_CONFIG = {
  'Looks Safe':        { cls: 'verdict-banner--safe',      icon: '✅', label: 'Threat Assessment' },
  'Suspicious':        { cls: 'verdict-banner--suspicious', icon: '⚠️', label: 'Threat Assessment' },
  'High Risk':         { cls: 'verdict-banner--high-risk',  icon: '🚨', label: 'Threat Assessment' },
  'Phishing Detected': { cls: 'verdict-banner--phishing',   icon: '🎣', label: '⚡ Active Threat Detected' },
}

const DEFAULT_CONFIG = { cls: 'verdict-banner--suspicious', icon: '❓', label: 'Threat Assessment' }

function formatTimestamp(isoStr) {
  try {
    return new Date(isoStr).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })
  } catch { return isoStr }
}

export default function VerdictBanner({ verdict, score, aiResult, timestamp }) {
  // Support both v2 (verdict+score) and v1 (aiResult) prop shapes
  const resolvedVerdict = verdict ?? aiResult?.verdict ?? 'Suspicious'
  const resolvedReason  = aiResult?.reason ?? ''
  const config          = VERDICT_CONFIG[resolvedVerdict] ?? DEFAULT_CONFIG

  return (
    <div
      className={`verdict-banner ${config.cls}`}
      role="region"
      aria-label={`Security verdict: ${resolvedVerdict}`}
    >
      {/* Header row */}
      <div className="verdict-banner__header">
        <div className="verdict-banner__icon" aria-hidden="true">{config.icon}</div>
        <div style={{ flex: 1 }}>
          <div className="verdict-banner__label">{config.label}</div>
          <div className="verdict-banner__verdict">{resolvedVerdict}</div>
        </div>
        {/* Score pill */}
        {score !== undefined && (
          <div className="verdict-score-pill" aria-label={`Risk score ${score} out of 100`}>
            <span className="verdict-score-pill__num">{score}</span>
            <span className="verdict-score-pill__denom">/100</span>
          </div>
        )}
      </div>

      <div className="verdict-banner__divider" aria-hidden="true" />

      {/* Reason */}
      {resolvedReason && (
        <>
          <div className="verdict-banner__reason-label">AI Analysis</div>
          <p className="verdict-banner__reason">{resolvedReason}</p>
        </>
      )}

      {/* Timestamp */}
      {timestamp && (
        <div className="verdict-banner__timestamp">
          <span aria-hidden="true">🕐</span>
          Scanned: {formatTimestamp(timestamp)}
        </div>
      )}
    </div>
  )
}
