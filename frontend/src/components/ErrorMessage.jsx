/**
 * ErrorMessage.jsx
 * ----------------
 * Displays a styled error alert with a dismiss button.
 *
 * Props:
 *   message   string  – error text to display
 *   onDismiss fn      – called when the user dismisses the error
 */

export default function ErrorMessage({ message, onDismiss }) {
  if (!message) return null

  return (
    <div
      className="error-message"
      role="alert"
      aria-live="assertive"
      id="error-message-banner"
    >
      <span className="error-message__icon" aria-hidden="true">⛔</span>

      <div className="error-message__body">
        <p className="error-message__title">Analysis Failed</p>
        <p className="error-message__text">{message}</p>

        <button
          id="dismiss-error-btn"
          className="error-message__dismiss"
          onClick={onDismiss}
          aria-label="Dismiss error message"
        >
          Dismiss
        </button>
      </div>
    </div>
  )
}
