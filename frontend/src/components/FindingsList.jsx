/**
 * FindingsList.jsx
 * ----------------
 * Renders the technical security findings as a styled table.
 * Each row shows:  Feature Name | Value (colour-coded) | Explanation
 *
 * Props:
 *   findings  Array<{ name: string, value: string, explain: string }>
 */

// ── Value Colour Classification ──────────────────────────────────────────────

/**
 * Determine the CSS modifier class for the Value cell based on
 * the presence of status emoji indicators appended by the backend.
 */
function valueClass(value) {
  if (value.includes('✓'))  return 'findings__value--safe'
  if (value.includes('✗'))  return 'findings__value--danger'
  if (value.includes('⚠'))  return 'findings__value--warn'
  return ''
}

// ── Component ────────────────────────────────────────────────────────────────

export default function FindingsList({ findings }) {
  if (!findings || findings.length === 0) return null

  return (
    <div className="card findings">
      {/* Section header */}
      <div className="findings__header">
        <h2 className="findings__title">Technical Findings</h2>
        <span className="findings__count">{findings.length} checks</span>
      </div>

      {/* Table */}
      <div className="findings__table-wrap" role="region" aria-label="Security findings table">
        <table className="findings__table">
          <thead>
            <tr>
              <th scope="col">Feature</th>
              <th scope="col">Value</th>
              <th scope="col">Explanation</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding, idx) => (
              <tr key={idx}>
                <td className="findings__feature-name">{finding.name}</td>
                <td className={`findings__value ${valueClass(finding.value)}`}>
                  {finding.value}
                </td>
                <td className="findings__explain">{finding.explain}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
