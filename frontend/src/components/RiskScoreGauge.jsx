/**
 * RiskScoreGauge.jsx
 * ------------------
 * Animated circular gauge displaying the 0–100 risk score.
 * Color transitions: green → yellow → orange → red
 *
 * Props:
 *   score   number  0–100
 *   verdict string
 */

import { useEffect, useState } from 'react'

const VERDICT_COLORS = {
  'Looks Safe':       { stroke: '#22c55e', glow: 'rgba(34,197,94,0.4)'   },
  'Suspicious':       { stroke: '#f59e0b', glow: 'rgba(245,158,11,0.4)'  },
  'High Risk':        { stroke: '#f97316', glow: 'rgba(249,115,22,0.4)'  },
  'Phishing Detected':{ stroke: '#ef4444', glow: 'rgba(239,68,68,0.4)'   },
}

const SEVERITY_LABEL = {
  'Looks Safe':       'LOW',
  'Suspicious':       'MEDIUM',
  'High Risk':        'HIGH',
  'Phishing Detected':'CRITICAL',
}

export default function RiskScoreGauge({ score, verdict, confidence }) {
  const [displayed, setDisplayed] = useState(0)

  // Animate counter up to score
  useEffect(() => {
    setDisplayed(0)
    let frame
    const step = () => {
      setDisplayed(prev => {
        if (prev >= score) return score
        frame = requestAnimationFrame(step)
        return Math.min(prev + Math.ceil(score / 40), score)
      })
    }
    frame = requestAnimationFrame(step)
    return () => cancelAnimationFrame(frame)
  }, [score])

  const config  = VERDICT_COLORS[verdict] ?? VERDICT_COLORS['Suspicious']
  const severity = SEVERITY_LABEL[verdict] ?? 'UNKNOWN'

  // SVG arc math (r=52, circumference ≈ 326.7)
  const R    = 52
  const C    = 2 * Math.PI * R
  const dash = (displayed / 100) * C

  return (
    <div className="gauge-wrapper" aria-label={`Risk score: ${score} out of 100`}>
      <div className="gauge-label-top">Risk Score</div>

      <div className="gauge-svg-wrap">
        <svg viewBox="0 0 120 120" className="gauge-svg">
          {/* Track */}
          <circle
            cx="60" cy="60" r={R}
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="10"
          />
          {/* Progress arc */}
          <circle
            cx="60" cy="60" r={R}
            fill="none"
            stroke={config.stroke}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${C}`}
            strokeDashoffset="0"
            transform="rotate(-90 60 60)"
            style={{
              transition: 'stroke-dasharray 0.05s linear',
              filter: `drop-shadow(0 0 6px ${config.glow})`,
            }}
          />
          {/* Score number */}
          <text
            x="60" y="56"
            textAnchor="middle"
            dominantBaseline="middle"
            fill={config.stroke}
            fontSize="22"
            fontWeight="800"
            fontFamily="'JetBrains Mono', monospace"
          >
            {displayed}
          </text>
          <text
            x="60" y="73"
            textAnchor="middle"
            fill="rgba(255,255,255,0.4)"
            fontSize="9"
            fontFamily="Inter, sans-serif"
            fontWeight="500"
          >
            / 100
          </text>
        </svg>
      </div>

      <div
        className={`gauge-severity gauge-severity--${severity.toLowerCase()}`}
        aria-label={`Severity: ${severity}`}
      >
        {severity}
      </div>

      {confidence !== undefined && (
        <div className="gauge-confidence" title="Detection Confidence">
          Confidence: <strong>{confidence}%</strong>
        </div>
      )}
    </div>
  )
}
