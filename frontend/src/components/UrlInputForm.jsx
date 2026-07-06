/**
 * UrlInputForm.jsx
 * ----------------
 * URL input box and Analyze button with client-side validation.
 * Props:
 *   url        {string}   – controlled input value
 *   onUrlChange {fn}      – (newValue: string) => void
 *   onSubmit   {fn}       – () => void  triggered on form submit
 *   loading    {boolean}  – disables controls while fetching
 */

import { useState } from 'react'

// Basic URL sanity check (scheme + non-empty host)
const URL_PATTERN = /^(https?:\/\/)?[\w\-]+(\.[\w\-]+)+([\w\-._~:/?#[\]@!$&'()*+,;=%]*)?$/i

export default function UrlInputForm({ url, onUrlChange, onSubmit, loading }) {
  const [touched, setTouched] = useState(false)

  const isInvalid = touched && url.trim().length > 0 && !URL_PATTERN.test(url.trim())

  function handleSubmit(e) {
    e.preventDefault()
    setTouched(true)
    if (!url.trim()) return
    if (isInvalid) return
    onSubmit()
  }

  function handleChange(e) {
    onUrlChange(e.target.value)
    if (!touched) setTouched(true)
  }

  return (
    <div className="card url-form">
      <div className="url-form__label">
        <span className="url-form__label-icon">🔍</span>
        Enter URL to Analyze
      </div>

      <form onSubmit={handleSubmit} noValidate id="url-scan-form">
        <div className="url-form__row">
          <input
            id="url-input"
            className="url-form__input"
            type="url"
            value={url}
            onChange={handleChange}
            placeholder="https://example.com  or  paste any suspicious link…"
            disabled={loading}
            autoComplete="off"
            spellCheck={false}
            aria-label="URL to analyze"
            aria-invalid={isInvalid}
            aria-describedby={isInvalid ? 'url-validation-msg' : undefined}
          />

          <button
            id="analyze-btn"
            className="url-form__btn"
            type="submit"
            disabled={loading || !url.trim()}
            aria-busy={loading}
          >
            {loading ? (
              <>
                <span aria-hidden="true">⏳</span>
                Scanning…
              </>
            ) : (
              <>
                <span aria-hidden="true">🛡️</span>
                Analyze
              </>
            )}
          </button>
        </div>

        {isInvalid && (
          <p id="url-validation-msg" className="url-form__validation-msg" role="alert">
            ⚠ Please enter a valid URL (e.g. https://example.com)
          </p>
        )}
      </form>
    </div>
  )
}
