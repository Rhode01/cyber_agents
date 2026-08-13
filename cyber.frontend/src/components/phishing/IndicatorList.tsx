'use client'

import { useState } from 'react'

import { SeverityBadge } from '@/components/ui/Badge'
import { Well } from '@/components/ui/Card'
import { CATEGORY_ICON, ChevronRight, ShieldCheck } from '@/components/ui/icons'
import { cn } from '@/lib/utils'
import { CATEGORY_LABEL, CATEGORY_ORDER } from '@/types'
import type { Indicator, IndicatorCategory } from '@/types'

/**
 * The deterministic indicators behind a phishing verdict, grouped by category.
 *
 * **Everything here is rendered as text.** `fact`, `locus` and the evidence values embed
 * attacker-authored strings — a subject line, a filename, a link's visible text. React's
 * default escaping is the guard, so `dangerouslySetInnerHTML` must never appear in this file.
 * That is also why evidence values go through `renderValue` rather than being spread into
 * markup.
 *
 * Order matters: categories are shown strongest-evidence-first, matching how the rule engine
 * weights them. An analyst reading top to bottom sees the hardest-to-fake signals before the
 * softest. Sender authentication cannot be argued with; wording can.
 *
 * Each indicator's *evidence* is behind a disclosure. The fact and the rationale are the
 * finding; the raw key/value pairs are the audit trail, and showing twenty of them expanded
 * buries the six that matter.
 */

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

export function IndicatorList({ indicators }: { indicators: readonly Indicator[] }) {
  if (indicators.length === 0) {
    return (
      <Well className="flex items-start gap-2.5 py-3">
        <ShieldCheck className="mt-0.5 size-4 shrink-0 text-status-ok" aria-hidden />
        <p className="text-body-sm text-text-secondary">
          No indicator fired. Sender authentication, identity, links, attachments and message
          content were all checked — this is a statement about those rules, not a guarantee the
          message is safe.
        </p>
      </Well>
    )
  }

  const grouped = new Map<IndicatorCategory, Indicator[]>()
  for (const indicator of indicators) {
    const existing = grouped.get(indicator.category)
    if (existing) existing.push(indicator)
    else grouped.set(indicator.category, [indicator])
  }

  const ordered = CATEGORY_ORDER.filter((category) => grouped.has(category))
  // Any category the backend adds that this build does not know about still renders, rather
  // than silently disappearing from an analyst's view.
  const unknown = [...grouped.keys()].filter((category) => !CATEGORY_ORDER.includes(category))

  return (
    <div className="space-y-4">
      {[...ordered, ...unknown].map((category) => {
        const found = grouped.get(category) ?? []
        const Icon = CATEGORY_ICON[category]
        return (
          <section key={category}>
            <h4 className="flex items-center gap-2 text-body-sm font-semibold text-text-primary">
              {Icon ? <Icon className="size-4 text-text-tertiary" aria-hidden /> : null}
              {CATEGORY_LABEL[category] ?? category}
              <span
                className="rounded-full bg-surface-sunken px-1.5 py-0.5 text-caption font-normal text-text-tertiary"
                data-numeric
              >
                {found.length}
              </span>
            </h4>
            <ul className="mt-2 space-y-2">
              {found
                // Heaviest first within a category, so the strongest reason leads.
                .slice()
                .sort((a, b) => b.weight - a.weight)
                .map((indicator) => (
                  <IndicatorRow key={indicator.indicator_id} indicator={indicator} />
                ))}
            </ul>
          </section>
        )
      })}
    </div>
  )
}

function IndicatorRow({ indicator }: { indicator: Indicator }) {
  const [open, setOpen] = useState(false)

  const evidence = Object.entries(indicator.evidence).filter(
    ([key]) => !HIDDEN_EVIDENCE_KEYS.has(key),
  )

  return (
    <li className="rounded-md border border-border-subtle bg-surface-sunken">
      <div className="px-3 py-2.5">
        <div className="flex flex-wrap items-start gap-x-2.5 gap-y-1.5">
          <SeverityBadge severity={indicator.severity_floor} size="sm" className="shrink-0" />
          {/* Untrusted. A deterministic sentence, but one that embeds attacker strings. */}
          <p className="min-w-0 flex-1 text-body-sm text-text-primary">{indicator.fact}</p>
        </div>

        <p className="mt-1.5 text-body-sm text-text-secondary">{indicator.rationale}</p>

        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-caption text-text-tertiary">
          <code className="font-mono">{indicator.rule_id}</code>
          {/* Untrusted: `attachment:invoice.pdf.exe` embeds a filename the sender chose. */}
          <span className="font-mono">{indicator.locus}</span>
          <span data-numeric>weight {indicator.weight.toFixed(2)}</span>
          {evidence.length > 0 ? (
            <button
              type="button"
              aria-expanded={open}
              onClick={() => setOpen(!open)}
              className="ml-auto inline-flex items-center gap-1 text-caption text-text-tertiary transition-colors hover:text-text-secondary"
            >
              <ChevronRight
                className={cn(
                  'size-3 transition-transform duration-(--duration-fast)',
                  open && 'rotate-90',
                )}
                aria-hidden
              />
              {open ? 'Hide' : 'Show'} evidence
              <span data-numeric>({evidence.length})</span>
            </button>
          ) : null}
        </div>
      </div>

      {open && evidence.length > 0 ? (
        <dl className="grid gap-x-4 gap-y-1.5 border-t border-border-subtle px-3 py-2.5 sm:grid-cols-[minmax(0,10rem)_1fr]">
          {evidence.map(([key, value]) => (
            <div key={key} className="contents">
              <dt className="text-caption uppercase tracking-wide text-text-tertiary">
                {key.replace(/_/g, ' ')}
              </dt>
              {/* Text only. This is attacker-controlled content. */}
              <dd className="min-w-0 break-words font-mono text-caption text-text-secondary">
                {renderValue(value)}
              </dd>
            </div>
          ))}
        </dl>
      ) : null}
    </li>
  )
}
