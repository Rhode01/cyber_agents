'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'

import { fetchBackendHealth, fetchFindings } from '@/lib/api'
import type { AgentTraceEntry, BackendHealth, Finding, Severity } from '@/lib/types'

type HealthState =
  | { kind: 'loading' }
  | { kind: 'ok'; health: BackendHealth }
  | { kind: 'error'; message: string }

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_META: Record<Severity, { label: string; color: string }> = {
  critical: { label: 'Critical', color: '#f43f5e' },
  high: { label: 'High', color: '#fb923c' },
  medium: { label: 'Medium', color: '#fbbf24' },
  low: { label: 'Low', color: '#38bdf8' },
  info: { label: 'Info', color: '#64748b' },
}

const MODULES = [
  ['frontend', 'localhost:3000'],
  ['backend', 'localhost:8000'],
  ['ai.engine', 'localhost:8003'],
  ['mcpserver', 'localhost:8004'],
  ['postgres', 'localhost:5432'],
  ['redis', 'localhost:6379'],
] as const

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

function AgentChip({ agent }: { agent: string }) {
  return <span className={`agent-chip agent-${agent}`}>{agent}</span>
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{SEVERITY_META[severity].label}</span>
}

export default function Home() {
  const [health, setHealth] = useState<HealthState>({ kind: 'loading' })
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [findingsError, setFindingsError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false

    fetchBackendHealth()
      .then((h) => {
        if (!cancelled) setHealth({ kind: 'ok', health: h })
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setHealth({
            kind: 'error',
            message: error instanceof Error ? error.message : 'Unknown error',
          })
        }
      })

    fetchFindings(200)
      .then((data) => {
        if (!cancelled) setFindings(data.items)
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setFindingsError(error instanceof Error ? error.message : 'Unknown error')
        }
      })

    return () => {
      cancelled = true
    }
  }, [attempt])

  function check() {
    setHealth({ kind: 'loading' })
    setAttempt((n) => n + 1)
  }

  const stats = useMemo(() => {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    const byAgent: Record<string, number> = {}
    for (const f of findings ?? []) {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1
      byAgent[f.agent] = (byAgent[f.agent] ?? 0) + 1
    }
    const total = findings?.length ?? 0
    return { counts, byAgent, total }
  }, [findings])

  const maxSeverity = Math.max(1, ...SEVERITIES.map((s) => stats.counts[s]))
  const recent = findings?.slice(0, 6) ?? []

  const criticalPct = stats.total ? (stats.counts.critical / stats.total) * 100 : 0

  return (
    <main>
      <div className="page-title">
        <div>
          <span className="eyebrow">Security Operations</span>
          <h1>Detection Overview</h1>
          <p className="subtitle">
            AI-driven agent analysis across web applications, networks, vulnerability surfaces and
            phishing campaigns.
          </p>
        </div>

        {health.kind === 'ok' && (
          <span className="pill ok">
            <span className="dot" />
            System operational
          </span>
        )}
        {health.kind === 'error' && <span className="pill bad">● Backend offline</span>}
        {health.kind === 'loading' && <span className="pill pending">checking…</span>}
      </div>

      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1.75rem' }}>
        <Link href="/run" className="btn btn-primary">
          ▶ Run Agent
        </Link>
        <Link href="/findings" className="btn">
          View Findings
        </Link>
        <Link href="/reports" className="btn">
          Reports Dashboard
        </Link>
      </div>

      <div className="stat-grid">
        <div className="stat-card accent">
          <div className="label">Total Findings</div>
          <div className="value">{stats.total}</div>
          <div className="sub">across all agents</div>
        </div>
        <div className="stat-card critical">
          <div className="label">Critical</div>
          <div className="value">{stats.counts.critical}</div>
          <div className="sub">{criticalPct.toFixed(0)}% of all detections</div>
        </div>
        <div className="stat-card high">
          <div className="label">High</div>
          <div className="value">{stats.counts.high}</div>
          <div className="sub">requires attention</div>
        </div>
        <div className="stat-card ok">
          <div className="label">Agents Active</div>
          <div className="value">{Object.keys(stats.byAgent).length}</div>
          <div className="sub">of 4 detection agents</div>
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: '1rem' }}>
        <section className="panel">
          <h2>Severity distribution</h2>
          {findingsError ? (
            <p className="error">{findingsError}</p>
          ) : stats.total === 0 ? (
            <p style={{ color: 'var(--muted)', margin: 0 }}>
              No findings yet — run an agent to populate the dashboard.
            </p>
          ) : (
            <>
              <div className="dist-bar">
                {SEVERITIES.map((sev) => (
                  <div
                    key={sev}
                    className="dist-seg"
                    style={{
                      width: `${(stats.counts[sev] / maxSeverity) * 100}%`,
                      background: SEVERITY_META[sev].color,
                    }}
                  />
                ))}
              </div>
              <div className="dist-legend">
                {SEVERITIES.map((sev) => (
                  <div key={sev} className="item">
                    <span
                      className="swatch"
                      style={{ background: SEVERITY_META[sev].color }}
                    />
                    {SEVERITY_META[sev].label}
                    <strong style={{ color: 'var(--text)' }}>{stats.counts[sev]}</strong>
                  </div>
                ))}
              </div>
            </>
          )}
        </section>

        <section className="panel">
          <h2>Coverage by agent</h2>
          {stats.total === 0 ? (
            <p style={{ color: 'var(--muted)', margin: 0 }}>No agent activity yet.</p>
          ) : (
            <ul className="ports">
              {Object.entries(stats.byAgent)
                .sort((a, b) => b[1] - a[1])
                .map(([agent, count]) => (
                  <li key={agent}>
                    <AgentChip agent={agent} />
                    <span>{count} findings</span>
                  </li>
                ))}
            </ul>
          )}
        </section>
      </div>

      <section className="panel">
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '0.75rem',
          }}
        >
          <h2 style={{ margin: 0 }}>Latest detections</h2>
          <Link href="/findings" style={{ fontSize: '0.85rem', fontWeight: 700 }}>
            View all →
          </Link>
        </div>

        {findingsError && <p className="error">{findingsError}</p>}
        {!findingsError && findings === null && (
          <span className="status pending">Loading detections…</span>
        )}
        {!findingsError && findings && findings.length === 0 && (
          <p style={{ color: 'var(--muted)', margin: 0 }}>
            No findings yet. Run an agent from the{' '}
            <Link href="/run" style={{ fontWeight: 700 }}>
              Run Agent
            </Link>{' '}
            page.
          </p>
        )}

        {recent.map((f) => (
          <Link key={f.id} href={`/findings/${f.id}`} className="finding-row">
            <SeverityBadge severity={f.severity} />
            <div className="meta">
              <div className="title">{f.title}</div>
              <div className="sub">
                {f.asset ?? f.source} · {formatWhen(f.detected_at)}
              </div>
            </div>
            <AgentChip agent={f.agent} />
          </Link>
        ))}
      </section>

      <section className="panel">
        <h2>Recent Agent Activity</h2>
        {findingsError ? (
          <p className="error">{findingsError}</p>
        ) : findings === null ? (
          <span className="status pending">Loading activity…</span>
        ) : (() => {
          const recentTraces = findings
            .filter((f) => Array.isArray(f.evidence?.agent_trace) && f.evidence.agent_trace.length > 0)
            .slice(0, 2);

          if (recentTraces.length === 0) {
            return <p style={{ color: 'var(--muted)', margin: 0 }}>No agent tool traces recorded yet.</p>;
          }

          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {recentTraces.map((f) => (
                <div key={`trace-${f.id}`} style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' }}>
                  <div style={{ padding: '0.5rem 1rem', background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{f.title}</span>
                    <AgentChip agent={f.agent} />
                  </div>
                  <div style={{ padding: '1rem', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--muted)', maxHeight: '250px', overflowY: 'auto' }}>
                    {(f.evidence.agent_trace as AgentTraceEntry[]).map((trace, idx) => (
                      <div key={idx} style={{ marginBottom: '0.5rem' }}>
                        {trace.type === 'tool_call' ? (
                          <div style={{ color: 'var(--ok)' }}>
                            <span style={{ opacity: 0.5 }}>$</span> {trace.tool} {JSON.stringify(trace.args)}
                          </div>
                        ) : (
                          <div style={{ paddingLeft: '1rem', borderLeft: '2px solid var(--border)', opacity: 0.8, marginTop: '0.25rem' }}>
                            {trace.result}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          );
        })()}
      </section>

      <section className="panel">
        <h2>Module map</h2>
        <ul className="ports">
          {MODULES.map(([name, address]) => (
            <li key={name}>
              <span style={{ fontWeight: 600 }}>{name}</span>
              <span>{address}</span>
            </li>
          ))}
        </ul>
        <div style={{ marginTop: '1rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {health.kind === 'ok' && <span className="module-state">Backend {health.health.version}</span>}
          <button type="button" className="btn btn-ghost" onClick={check} style={{ padding: '0.4rem 0.8rem' }}>
            Check again
          </button>
        </div>
      </section>

      {health.kind === 'error' && (
        <section className="panel" style={{ borderColor: 'rgba(251,113,133,0.3)' }}>
          <h2 style={{ color: 'var(--bad)' }}>Backend unreachable</h2>
          <p className="error">{health.message}</p>
          <p className="error">
            Start it with <code>make up</code> or <code>make dev-backend</code>.
          </p>
        </section>
      )}
    </main>
  )
}
