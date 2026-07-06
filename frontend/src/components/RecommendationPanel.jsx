/**
 * RecommendationPanel.jsx
 * -----------------------
 * Displays the AI-generated security recommendations as an action list.
 * Also shows the ML model prediction badge.
 *
 * Props:
 *   aiExplanation { summary, recommendations, fallback }
 *   mlResult      { available, prediction, confidence }
 */

export default function RecommendationPanel({ aiExplanation, mlResult }) {
  if (!aiExplanation) return null

  const { summary, recommendations = [], fallback } = aiExplanation
  const mlAvailable  = mlResult?.available
  const mlPrediction = mlResult?.prediction
  const mlConf       = mlResult?.confidence

  return (
    <div className="card rec-panel">
      {/* Header */}
      <div className="findings__header">
        <h2 className="findings__title">
          {fallback ? 'Security Analysis' : 'AI Security Analysis'}
        </h2>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          {mlAvailable && (
            <span
              className={`ml-badge ml-badge--${mlPrediction === 'phishing' ? 'danger' : 'safe'}`}
              title={`ML Model: ${mlPrediction} (${mlConf}% confidence)`}
            >
              🤖 ML: {mlPrediction === 'phishing' ? `Phishing ${mlConf}%` : `Legit ${mlConf}%`}
            </span>
          )}
          {fallback && (
            <span className="ml-badge ml-badge--neutral" title="Gemini AI unavailable — rule-based explanation used">
              ⚙ Rule-based
            </span>
          )}
        </div>
      </div>

      {/* AI / Rule-based Summary */}
      {summary && (
        <div className="rec-summary">
          <p>{summary}</p>
        </div>
      )}

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <div className="rec-list">
          <div className="rec-list__label">Recommendations</div>
          <ul>
            {recommendations.map((rec, i) => (
              <li key={i} className="rec-item">
                <span className="rec-item__bullet" aria-hidden="true">→</span>
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
