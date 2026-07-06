/**
 * LoadingSpinner.jsx
 * ------------------
 * Animated scanning overlay shown while the backend is processing.
 * Cycles through descriptive status messages to show progress.
 */

import { useEffect, useState } from 'react'

const STEPS = [
  'Resolving DNS records…',
  'Checking SSL certificate…',
  'Probing WHOIS data…',
  'Scanning URL structure…',
  'Querying AI analyzer…',
  'Compiling threat report…',
]

export default function LoadingSpinner() {
  const [stepIndex, setStepIndex] = useState(0)

  useEffect(() => {
    const interval = setInterval(() => {
      setStepIndex((i) => (i + 1) % STEPS.length)
    }, 1400)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="card loading-container" role="status" aria-live="polite" aria-label="Scanning URL">
      {/* Triple ring scanner animation */}
      <div className="loading-scanner" aria-hidden="true">
        <div className="loading-scanner__ring" />
        <div className="loading-scanner__ring" />
        <div className="loading-scanner__ring" />
        <div className="loading-scanner__dot">🔬</div>
      </div>

      <div className="loading-text">
        <p className="loading-text__title">Running Security Analysis</p>
        <p className="loading-text__steps" aria-live="polite">
          {STEPS[stepIndex]}
        </p>
      </div>
    </div>
  )
}
