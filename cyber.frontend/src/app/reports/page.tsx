'use client'

import { useEffect, useMemo, useState } from 'react'
import { fetchFindings } from '@/lib/api'
import { SeverityDot } from '@/components/SeverityBadge'
import {
  SEVERITY_CLASS,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  emptySeverityCounts,
} from '@/lib/severity'
import { cn } from '@/lib/utils'
import type { Finding } from '@/types'

export default function ReportsPage() {
  const [data, setData] = useState<{ items: Finding[] } | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchFindings(200)
      .then(setData)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const metrics = useMemo(() => {
    const items = data?.items ?? []
    const bySeverity = emptySeverityCounts()
    const byAgent: Record<string, number> = {}
    const byAsset: Record<string, number> = {}

    for (const f of items) {
      bySeverity[f.severity]++
      byAgent[f.agent] = (byAgent[f.agent] ?? 0) + 1
      if (f.asset) byAsset[f.asset] = (byAsset[f.asset] ?? 0) + 1
    }

    const maxSeverity = Math.max(1, ...SEVERITY_ORDER.map((s) => bySeverity[s]))
    const topAssets = Object.entries(byAsset).sort((a, b) => b[1] - a[1]).slice(0, 5)
    const riskScore = items.length
      ? Math.round(
          (bySeverity.critical * 10 + bySeverity.high * 7 + bySeverity.medium * 4 + bySeverity.low * 2) /
            Math.max(1, items.length),
        )
      : 0

    return { total: items.length, bySeverity, byAgent, byAsset, topAssets, maxSeverity, riskScore }
  }, [data])

  if (loading)
    return (
      <main>
        <span className="status pending">Loading report data…</span>
      </main>
    )
  if (error)
    return (
      <main>
        <span className="status bad">Error: {error}</span>
      </main>
    )

  return (
    <main>
      <div className="page-title">
        <div>
          <span className="eyebrow">Analytics</span>
          <h1>Reports Dashboard</h1>
          <p className="subtitle">Aggregated posture across all detection agents.</p>
        </div>
        <button type="button" className="btn btn-ghost" onClick={() => window.print()}>
          Print Report
        </button>
      </div>

      {metrics.total === 0 ? (
        <section className="panel">
          <p style={{ color: 'var(--muted)', margin: 0 }}>
            No findings available to generate reports.
          </p>
        </section>
      ) : (
        <>
          <div className="stat-grid">
            <div className="stat-card accent">
              <div className="label">Total Findings</div>
              <div className="value">{metrics.total}</div>
            </div>
            <div className="stat-card critical">
              <div className="label">Risk Score</div>
              <div className="value">{metrics.riskScore}/10</div>
              <div className="sub">severity-weighted posture</div>
            </div>
            <div className="stat-card ok">
              <div className="label">Agents Active</div>
              <div className="value">{Object.keys(metrics.byAgent).length}</div>
            </div>
            <div className="stat-card high">
              <div className="label">Assets Affected</div>
              <div className="value">{Object.keys(metrics.byAsset).length}</div>
            </div>
          </div>

          <section className="panel">
            <h2>Severity distribution</h2>
            <div className="dist-bar">
              {SEVERITY_ORDER.map((sev) => (
                <div
                  key={sev}
                  className={cn('dist-seg', SEVERITY_CLASS[sev].fill)}
                  style={{ width: `${(metrics.bySeverity[sev] / metrics.maxSeverity) * 100}%` }}
                />
              ))}
            </div>
            <div className="dist-legend">
              {SEVERITY_ORDER.map((sev) => (
                <div key={sev} className="item">
                  <SeverityDot severity={sev} className="size-2.5" />
                  {SEVERITY_LABEL[sev]}
                  <strong style={{ color: 'var(--text)' }}>{metrics.bySeverity[sev]}</strong>
                </div>
              ))}
            </div>
          </section>

          <div className="grid-3">
            <section className="panel">
              <h2>Findings by Agent</h2>
              <ul className="ports">
                {Object.entries(metrics.byAgent)
                  .sort((a, b) => b[1] - a[1])
                  .map(([agent, count]) => (
                    <li key={agent}>
                      <span className={`agent-chip agent-${agent}`} style={{ textTransform: 'none' }}>
                        {agent}
                      </span>
                      <strong>{count}</strong>
                    </li>
                  ))}
              </ul>
            </section>

            <section className="panel">
              <h2>Top Impacted Assets</h2>
              {metrics.topAssets.length > 0 ? (
                <ul className="ports">
                  {metrics.topAssets.map(([asset, count]) => (
                    <li key={asset}>
                      <code style={{ maxWidth: '70%', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {asset}
                      </code>
                      <strong>{count}</strong>
                    </li>
                  ))}
                </ul>
              ) : (
                <p style={{ color: 'var(--muted)', margin: 0 }}>No asset targets found.</p>
              )}
            </section>

            <section className="panel">
              <h2>Source Tools</h2>
              <ul className="ports">
                {(Object.entries(
                  (data?.items ?? []).reduce<Record<string, number>>((acc, f) => {
                    acc[f.source] = (acc[f.source] ?? 0) + 1
                    return acc
                  }, {}),
                ).sort((a, b) => b[1] - a[1])).map(([source, count]) => (
                  <li key={source}>
                    <span style={{ fontWeight: 600, textTransform: 'capitalize' }}>{source}</span>
                    <strong>{count}</strong>
                  </li>
                ))}
              </ul>
            </section>
          </div>
        </>
      )}
    </main>
  )
}
