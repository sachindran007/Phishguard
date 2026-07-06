/**
 * ThreatIntelPanel.jsx
 * --------------------
 * Displays Google Safe Browsing + VirusTotal results side by side.
 *
 * Props:
 *   threatIntel {
 *     safe_browsing: { checked, detected, source, details, detections, error }
 *     virustotal:    { checked, detected, source, details, detections, error }
 *     any_detected:  bool
 *   }
 */

function SourceCard({ data }) {
  if (!data) return null

  const { checked, detected, source, details, detections, error } = data

  let statusClass = 'ti-card--neutral'
  let icon        = '⏭️'
  let statusText  = 'Not Configured'

  if (error) {
    statusClass = 'ti-card--warn'
    icon        = '⚠️'
    statusText  = 'Check Failed'
  } else if (!checked) {
    statusClass = 'ti-card--neutral'
    icon        = '➖'
    statusText  = 'Not Configured'
  } else if (detected) {
    statusClass = 'ti-card--danger'
    icon        = '🚨'
    statusText  = detections > 0 ? `${detections} Detection(s)` : 'Threat Found'
  } else {
    statusClass = 'ti-card--safe'
    icon        = '✅'
    statusText  = 'Clean'
  }

  return (
    <div className={`ti-card ${statusClass}`}>
      <div className="ti-card__header">
        <span className="ti-card__icon" aria-hidden="true">{icon}</span>
        <div>
          <div className="ti-card__source">{source}</div>
          <div className="ti-card__status">{statusText}</div>
        </div>
      </div>
      {details && <p className="ti-card__details">{details}</p>}
      {error    && <p className="ti-card__error">Error: {error}</p>}
    </div>
  )
}

export default function ThreatIntelPanel({ threatIntel }) {
  if (!threatIntel) return null

  const { safe_browsing, virustotal, any_detected } = threatIntel

  return (
    <div className="card ti-panel">
      <div className="findings__header">
        <h2 className="findings__title">Threat Intelligence</h2>
        <span
          className={`findings__count ${any_detected ? 'findings__count--danger' : ''}`}
          style={any_detected ? { background: 'rgba(239,68,68,0.15)', color: '#ef4444', borderColor: 'rgba(239,68,68,0.4)' } : {}}
        >
          {any_detected ? '⚠ Threat Detected' : '✓ No Threats'}
        </span>
      </div>

      <div className="ti-grid">
        <SourceCard data={safe_browsing} />
        <SourceCard data={virustotal}    />
      </div>
    </div>
  )
}
