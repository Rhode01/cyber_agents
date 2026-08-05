'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'

import { fetchFindings } from '@/lib/api'
import type { Finding, Severity } from '@/lib/types'

const SEVERITY_META: Record<Severity, { label: string; color: string }> = {
  critical: { label: 'Critical', color: '#f43f5e' },
  high: { label: 'High', color: '#fb923c' },
  medium: { label: 'Medium', color: '#fbbf24' },
  low: { label: 'Low', color: '#38bdf8' },
  info: { label: 'Info', color: '#64748b' },
}

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

export default function FindingsPage() {
  const [data, setData] = useState<{ items: Finding[]; total: number } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchFindings(200)
      .then(setData)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const bySeverity = useMemo(() => {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of data?.items ?? []) counts[f.severity]++
    return counts
  }, [data])

  return (
    <main>
      <div className="page-title">
        <div>
          <span className="eyebrow">Detection Log</span>
          <h1>Findings</h1>
          <p className="subtitle">{data?.total ?? '…'} persisted detections across all agents.</p>
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
            {(Object.keys(SEVERITY_META) as Severity[]).map((sev) => (
              <div key={sev} className={`stat-card ${sev}`}>
                <div className="label">{SEVERITY_META[sev].label}</div>
                <div className="value">{bySeverity[sev]}</div>
              </div>
            ))}
          </div>

          <section className="panel">
            {data.items.length === 0 ? (
              <p style={{ color: 'var(--muted)', margin: 0 }}>
                No findings yet. Run an agent to create some.
              </p>
            ) : (
              data.items.map((finding) => (
                <Link
                  key={finding.id}
                  href={`/findings/${finding.id}`}
                  className="finding-row"
                  style={{ borderBottom: '1px solid var(--border)', borderRadius: 0 }}
                >
                  <span className={`badge sev-${finding.severity}`}>
                    {SEVERITY_META[finding.severity].label}
                  </span>
                  <div className="meta">
                    <div className="title">{finding.title}</div>
                    <div className="sub">
                      {finding.asset ?? 'No asset'} · {finding.source} · {formatWhen(finding.detected_at)}
                    </div>
                  </div>
                  <span className={`agent-chip agent-${finding.agent}`}>{finding.agent}</span>
                </Link>
              ))
            )}
          </section>
        </>
      )}
    </main>
  )
}
