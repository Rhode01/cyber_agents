/**
 * The deterministic indicators behind a phishing verdict, grouped by category.
 *
 * **Everything here is rendered as text.** `fact`, `locus` and the evidence values embed
 * attacker-authored strings - a subject line, a filename, a link's visible text. React's
 * default escaping is the guard, so `dangerouslySetInnerHTML` must never appear in this
 * file. That is also why evidence values go through `renderValue` rather than being
 * spread into markup.
 *
 * Order matters: categories are shown strongest-evidence-first, matching how the rule
 * engine weights them. An analyst reading top to bottom sees the hardest-to-fake signals
 * before the softest.
 */

import { CATEGORY_LABEL, CATEGORY_ORDER } from '@/types/intake'
import type { Indicator, IndicatorCategory } from '@/types/intake'

function renderValue(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

/** Evidence keys that repeat the fact sentence or are only useful to the engine. */
const HIDDEN_EVIDENCE_KEYS = new Set(['note', 'technique', 'locus'])

function EvidenceRows({ evidence }: { evidence: Record<string, unknown> }) {
  const entries = Object.entries(evidence).filter(([key]) => !HIDDEN_EVIDENCE_KEYS.has(key))
  if (entries.length === 0) return null

  return (
    <dl className="indicator-evidence">
      {entries.map(([key, value]) => (
        <div key={key}>
          <dt>{key.replace(/_/g, ' ')}</dt>
          {/* Text only. This is attacker-controlled content. */}
          <dd>{renderValue(value)}</dd>
        </div>
      ))}
    </dl>
  )
}

export default function IndicatorList({ indicators }: { indicators: Indicator[] }) {
  if (indicators.length === 0) {
    return (
      <p className="muted">
        No indicators fired. Sender authentication, identity, links, attachments and
        message content were all checked.
      </p>
    )
  }

  const grouped = new Map<IndicatorCategory, Indicator[]>()
  for (const indicator of indicators) {
    const existing = grouped.get(indicator.category)
    if (existing) existing.push(indicator)
    else grouped.set(indicator.category, [indicator])
  }

  const ordered = CATEGORY_ORDER.filter((category) => grouped.has(category))
  // Any category the backend adds that this list does not know about still renders,
  // rather than silently disappearing from an analyst's view.
  const unknown = [...grouped.keys()].filter((category) => !CATEGORY_ORDER.includes(category))

  return (
    <div className="indicator-groups">
      {[...ordered, ...unknown].map((category) => {
        const found = grouped.get(category) ?? []
        return (
          <section key={category} className="indicator-group">
            <h3>
              {CATEGORY_LABEL[category] ?? category}
              <span className="indicator-count">{found.length}</span>
            </h3>
            <ul>
              {found.map((indicator) => (
                <li key={indicator.indicator_id} className="indicator">
                  <div className="indicator-head">
                    <span className={`sev-dot sev-${indicator.severity_floor}`} />
                    <span className="indicator-fact">{indicator.fact}</span>
                  </div>
                  <div className="indicator-meta">
                    <code>{indicator.rule_id}</code>
                    <span>{indicator.locus}</span>
                    <span>weight {indicator.weight.toFixed(2)}</span>
                  </div>
                  <p className="indicator-why">{indicator.rationale}</p>
                  <EvidenceRows evidence={indicator.evidence} />
                </li>
              ))}
            </ul>
          </section>
        )
      })}
    </div>
  )
}
