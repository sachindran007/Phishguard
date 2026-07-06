/**
 * VisualScanPanel.jsx
 * -------------------
 * Displays the screenshot captured by Playwright and the AI vision verdict.
 *
 * Props:
 *   visualResult {
 *     checked:          bool
 *     visual_threat:    bool
 *     confidence:       number
 *     reason:           string
 *     detected_brands:  string[]
 *     has_login_form:   bool
 *     has_payment_form: bool
 *     screenshot_b64:   string
 *     error:            string
 *   }
 */

export default function VisualScanPanel({ visualResult }) {
  if (!visualResult || (!visualResult.checked && !visualResult.error)) return null

  const {
    visual_threat, confidence, reason, detected_brands,
    has_login_form, has_payment_form, screenshot_b64, error
  } = visualResult

  if (error) {
    return (
      <div className="card visual-panel visual-panel--error">
        <h2 className="findings__title">Visual Scanner</h2>
        <p className="ti-card__error" style={{ marginTop: '8px' }}>⚠️ {error}</p>
      </div>
    )
  }

  const statusClass = visual_threat ? 'visual-panel--danger' : 'visual-panel--safe'
  const icon = visual_threat ? '🚨' : '✅'

  return (
    <div className={`card visual-panel ${statusClass}`}>
      <div className="findings__header" style={{ marginBottom: '16px' }}>
        <h2 className="findings__title">AI Visual Scanner (Gemini Vision)</h2>
        <span
          className={`findings__count ${visual_threat ? 'findings__count--danger' : ''}`}
        >
          {icon} {visual_threat ? `Visual Threat Detected (${confidence}%)` : 'Looks Visually Safe'}
        </span>
      </div>

      <div className="visual-panel__content">
        {/* Screenshot column */}
        <div className="visual-panel__screenshot-wrap">
          {screenshot_b64 ? (
            <img
              src={`data:image/png;base64,${screenshot_b64}`}
              alt="Website screenshot captured by Playwright"
              className="visual-panel__image"
            />
          ) : (
            <div className="visual-panel__placeholder">No screenshot</div>
          )}
        </div>

        {/* Info column */}
        <div className="visual-panel__info">
          <p className="visual-panel__reason"><strong>AI Verdict:</strong> {reason}</p>

          <div className="visual-panel__tags">
            {has_login_form && <span className="v-tag v-tag--warn">Login Form</span>}
            {has_payment_form && <span className="v-tag v-tag--warn">Payment Form</span>}
            {detected_brands?.length > 0 && (
              <span className="v-tag v-tag--brand">Brands: {detected_brands.join(', ')}</span>
            )}
            {!has_login_form && !has_payment_form && detected_brands?.length === 0 && (
              <span className="v-tag v-tag--neutral">No sensitive elements detected</span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
