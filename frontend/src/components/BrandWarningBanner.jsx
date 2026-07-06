/**
 * BrandWarningBanner.jsx
 * -----------------------
 * Full-width critical alert shown when brand impersonation is detected.
 * Shows category, detection algorithm, character substitution, and risk details.
 *
 * Props:
 *   brandResult {
 *     brand_impersonation:    bool
 *     target_brand:           string
 *     category:               string
 *     similarity:             number (0-100)
 *     method:                 string
 *     matched_algorithm:      string
 *     character_substitution: bool
 *     homoglyph_detected:    bool
 *     suspicious_tld:         bool
 *     risk_added:             number
 *     detail:                 string
 *   }
 */

const METHOD_LABELS = {
  typosquatting:          'Typosquatting',
  homograph_substitution: 'Homograph Attack',
  prefix_suffix_abuse:    'Prefix/Suffix Abuse',
  subdomain_abuse:        'Subdomain Abuse',
  brand_keyword_combo:    'Brand + Keyword Abuse',
}

const ALGO_LABELS = {
  levenshtein:             'Levenshtein Distance',
  jaro_winkler:            'Jaro-Winkler Similarity',
  character_normalization: 'Character Normalization',
  pattern_match:           'Pattern Match',
  keyword_analysis:        'Keyword Analysis',
}

const CATEGORY_LABELS = {
  technology:        '💻 Technology',
  indian_technology: '🇮🇳 Indian Technology',
  government:        '🏛️ Government',
  payment:           '💳 Payment',
  banking:           '🏦 Banking',
  ecommerce:         '🛒 E-Commerce',
  crypto:            '🪙 Crypto',
  email:             '📧 Email',
}

export default function BrandWarningBanner({ brandResult }) {
  if (!brandResult?.brand_impersonation) return null

  const {
    target_brand, category, similarity, method, matched_algorithm,
    character_substitution, homoglyph_detected, suspicious_tld,
    risk_added, detail,
  } = brandResult

  const methodLabel = METHOD_LABELS[method] ?? method ?? 'Unknown'
  const algoLabel   = ALGO_LABELS[matched_algorithm] ?? matched_algorithm ?? ''
  const catLabel    = CATEGORY_LABELS[category] ?? category ?? ''

  return (
    <div
      className="brand-banner"
      role="alert"
      aria-label={`Brand impersonation warning: targeting ${target_brand}`}
    >
      <div className="brand-banner__icon" aria-hidden="true">🎣</div>

      <div className="brand-banner__body">
        <div className="brand-banner__title">
          Brand Impersonation Detected
        </div>
        <div className="brand-banner__subtitle">
          This domain is impersonating{' '}
          <strong className="brand-banner__brand">
            {target_brand.charAt(0).toUpperCase() + target_brand.slice(1)}
          </strong>
          {' '}with{' '}
          <strong>{similarity}%</strong> similarity
          {' '}via <span className="brand-banner__method">{methodLabel}</span>
        </div>

        {detail && (
          <p className="brand-banner__detail">{detail}</p>
        )}

        <div className="brand-banner__tags">
          {catLabel && (
            <span className="brand-banner__tag brand-banner__tag--category">
              {catLabel}
            </span>
          )}
          {algoLabel && (
            <span className="brand-banner__tag brand-banner__tag--algo">
              📐 {algoLabel}
            </span>
          )}
          {character_substitution && (
            <span className="brand-banner__tag brand-banner__tag--warn">
              🔤 Char Substitution
            </span>
          )}
          {homoglyph_detected && (
            <span className="brand-banner__tag brand-banner__tag--danger">
              🔠 Homoglyph Attack
            </span>
          )}
          {suspicious_tld && (
            <span className="brand-banner__tag brand-banner__tag--warn">
              🌐 Suspicious TLD
            </span>
          )}
          {risk_added > 0 && (
            <span className="brand-banner__tag brand-banner__tag--risk">
              ⚠️ +{risk_added} Risk
            </span>
          )}
        </div>
      </div>

      <div className="brand-banner__badge">
        {similarity}%<br />
        <span>Match</span>
      </div>
    </div>
  )
}
