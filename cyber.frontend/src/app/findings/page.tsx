'use client'

import { Suspense, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'

import { fetchFindings } from '@/lib/api'
import { SeverityBadge } from '@/components/SeverityBadge'
import { CveList, FindingTypeChip } from '@/components/FindingTypeChip'
import { PriorityRank } from '@/components/PriorityBreakdown'
import { SEVERITY_LABEL, SEVERITY_ORDER, SEVERITY_WEIGHT, emptySeverityCounts } from '@/lib/severity'
import { StatusChip } from '@/components/VerificationHistory'
import {
  FINDING_TYPE_LABEL,
  FINDING_TYPE_ORDER,
  OPEN_STATUSES,
  byPriority,
  formatLocation,
  readPriority,
} from '@/lib/findings'
import type { Finding, FindingType } from '@/types'

function formatWhen(iso: string): string {
  const then = new Date(iso)
  const diff = Date.now() - then.getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

/** Priority first, because the list exists to answer "what do I fix next?".
 *  Newest-first stays available for watching a run land. */
type SortKey = 'priority' | 'newest'

function FindingsView({ assetParam }: { assetParam: string | null }) {
  const [data, setData] = useState<{ items: Finding[]; total: number } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [sort, setSort] = useState<SortKey>('priority')
  const [typeFilter, setTypeFilter] = useState<FindingType | 'all'>('all')
  // Open by default: a resolved finding has been dealt with, and leaving it in the
  // list competes for attention with the ones that have not.
  const [showClosed, setShowClosed] = useState(false)

  useEffect(() => {
    // Filtered server-side, so drilling into one asset stays correct past the
    // page size rather than filtering whatever happened to be fetched.
    //
    // No `setLoading(true)` here: the caller remounts this component when the
    // asset changes, so `loading` starts true again on its own. Setting it
    // synchronously inside the effect would be a cascading render.
    fetchFindings(200, 0, assetParam ?? undefined)
      .then(setData)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [assetParam])

  // Memoised, not `data?.items ?? []`: that allocates a new array on every render,
  // so every useMemo below it would recompute on every render.
  const items = useMemo(() => data?.items ?? [], [data])

  const bySeverity = useMemo(() => {
    const counts = emptySeverityCounts()
    for (const f of items) counts[f.severity]++
    return counts
  }, [items])

  /** Only the kinds actually present, so the filter never offers an empty view. */
  const presentTypes = useMemo(() => {
    const seen = new Set(items.map((f) => f.finding_type))
    return FINDING_TYPE_ORDER.filter((type) => seen.has(type))
  }, [items])

  const closedCount = useMemo(
    () => items.filter((f) => !OPEN_STATUSES.includes(f.status)).length,
    [items],
  )

  const visible = useMemo(() => {
    let filtered = showClosed ? items : items.filter((f) => OPEN_STATUSES.includes(f.status))
    if (typeFilter !== 'all') filtered = filtered.filter((f) => f.finding_type === typeFilter)
    const sorted = [...filtered]
    if (sort === 'priority') sorted.sort(byPriority(SEVERITY_WEIGHT))
    else sorted.sort((a, b) => Date.parse(b.detected_at) - Date.parse(a.detected_at))
    return sorted
  }, [items, sort, typeFilter, showClosed])

  return (
    <main>
      <div className="page-title">
        <div>
          <span className="eyebrow">Detection Log</span>
          <h1>Findings</h1>
          <p className="subtitle">
            {assetParam ? (
              <>
                {data?.total ?? '…'} detections on <code>{assetParam}</code> ·{' '}
                <Link href="/findings" style={{ fontWeight: 700 }}>
                  show all assets
                </Link>
              </>
            ) : (
              <>{data?.total ?? '…'} persisted detections across all agents.</>
            )}
          </p>
        </div>
      </div>

      {loading && (
        <section className="panel">
          <span className="status pending">Loading findings…</span>
        </section>
      )}

      {error && (
        <section className="panel" style={{ borderColor: 'rgba(251,113,133,0.3)' }}>
          <span className="status bad">● Error</span>
          <p className="error">{error}</p>
        </section>
      )}

      {data && (
        <>
          <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))' }}>
            <div className="stat-card accent">
              <div className="label">Total</div>
              <div className="value">{data.total}</div>
            </div>
            {SEVERITY_ORDER.map((sev) => (
              <div key={sev} className={`stat-card ${sev}`}>
                <div className="label">{SEVERITY_LABEL[sev]}</div>
                <div className="value">{bySeverity[sev]}</div>
              </div>
            ))}
          </div>

          <section className="panel">
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <span className="mr-1 text-xs tracking-wide text-faint uppercase">Sort</span>
              <button
                type="button"
                onClick={() => setSort('priority')}
                aria-pressed={sort === 'priority'}
                className={
                  sort === 'priority'
                    ? 'rounded-md border border-accent/40 bg-accent/10 px-2.5 py-1 text-xs font-semibold text-accent'
                    : 'rounded-md border border-border bg-transparent px-2.5 py-1 text-xs text-muted hover:border-border-strong'
                }
              >
                Priority
              </button>
              <button
                type="button"
                onClick={() => setSort('newest')}
                aria-pressed={sort === 'newest'}
                className={
                  sort === 'newest'
                    ? 'rounded-md border border-accent/40 bg-accent/10 px-2.5 py-1 text-xs font-semibold text-accent'
                    : 'rounded-md border border-border bg-transparent px-2.5 py-1 text-xs text-muted hover:border-border-strong'
                }
              >
                Newest
              </button>

              {presentTypes.length > 1 && (
                <>
                  <span className="ml-3 mr-1 text-xs tracking-wide text-faint uppercase">Kind</span>
                  <select
                    value={typeFilter}
                    onChange={(event) => setTypeFilter(event.target.value as FindingType | 'all')}
                    aria-label="Filter by finding type"
                    className="rounded-md border border-border bg-bg-elev px-2 py-1 text-xs text-text"
                  >
                    <option value="all">All kinds ({items.length})</option>
                    {presentTypes.map((type) => (
                      <option key={type} value={type}>
                        {FINDING_TYPE_LABEL[type]} ({items.filter((f) => f.finding_type === type).length})
                      </option>
                    ))}
                  </select>
                </>
              )}

              {closedCount > 0 && (
                <label className="ml-3 flex cursor-pointer items-center gap-1.5 text-xs text-muted select-none">
                  <input
                    type="checkbox"
                    checked={showClosed}
                    onChange={(event) => setShowClosed(event.target.checked)}
                  />
                  Show {closedCount} closed
                </label>
              )}
            </div>

            {items.length === 0 ? (
              <p style={{ color: 'var(--muted)', margin: 0 }}>
                {assetParam
                  ? `No findings recorded on ${assetParam}.`
                  : 'No findings yet. Run an agent to create some.'}
              </p>
            ) : visible.length === 0 ? (
              <p style={{ color: 'var(--muted)', margin: 0 }}>
                No {FINDING_TYPE_LABEL[typeFilter as FindingType].toLowerCase()} findings.
              </p>
            ) : (
              visible.map((finding) => {
                const priority = readPriority(finding)
                return (
                  <Link
                    key={finding.id}
                    href={`/findings/${finding.id}`}
                    className="finding-row"
                    style={{ borderBottom: '1px solid var(--border)', borderRadius: 0 }}
                  >
                    {priority && <PriorityRank priority={priority} />}
                    <SeverityBadge severity={finding.severity} />
                    <div className="meta">
                      <div className="title">{finding.title}</div>
                      <div className="sub">
                        {formatLocation(finding)}
                        {finding.service ? ` · ${finding.service}` : ''} · {finding.source} ·{' '}
                        {formatWhen(finding.detected_at)}
                      </div>
                      {finding.cve_ids.length > 0 && (
                        <CveList cveIds={finding.cve_ids} className="mt-1.5" />
                      )}
                    </div>
                    <FindingTypeChip type={finding.finding_type} />
                    {!OPEN_STATUSES.includes(finding.status) && (
                      <StatusChip status={finding.status} />
                    )}
                    <span className={`agent-chip agent-${finding.agent}`}>{finding.agent}</span>
                  </Link>
                )
              })
            )}
          </section>
        </>
      )}
    </main>
  )
}

/**
 * Reads the asset filter and remounts the view when it changes.
 *
 * Keyed rather than synchronised: a fresh mount resets `loading` and the sort and
 * kind filters to their defaults, which is what switching asset should do anyway,
 * and it avoids setting state inside an effect to achieve the same thing.
 */
function FindingsRoute() {
  const assetParam = useSearchParams().get('asset')
  return <FindingsView key={assetParam ?? 'all'} assetParam={assetParam} />
}

/**
 * `useSearchParams` suspends during prerender, so the route needs a boundary or
 * `next build` fails it rather than falling back to client rendering.
 */
export default function FindingsPage() {
  return (
    <Suspense
      fallback={
        <main>
          <div className="page-title">
            <div>
              <span className="eyebrow">Detection Log</span>
              <h1>Findings</h1>
            </div>
          </div>
          <section className="panel">
            <span className="status pending">Loading findings…</span>
          </section>
        </main>
      }
    >
      <FindingsRoute />
    </Suspense>
  )
}
