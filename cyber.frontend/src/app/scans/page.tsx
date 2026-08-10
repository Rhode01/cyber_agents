'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { fetchFindings } from '@/lib/api'
import { SeverityBadge, SeverityDot } from '@/components/SeverityBadge'
import { SEVERITY_ORDER } from '@/lib/severity'
import type { Finding, AgentKind, Severity } from '@/types'

interface ScanSession {
  id: string
  agent: AgentKind | 'run'
  asset: string
  source: string
  date: string          // display timestamp, e.g. "2026-08-06 14:34"
  timestamp: string     // ISO timestamp used for sorting
  findings: Finding[]
  severities: Record<Severity, number>
  criticalCount: number
  highCount: number
  status: 'clean' | 'warning' | 'critical'
}


const AGENT_LABELS: Record<AgentKind, string> = {
  vulnerability: 'Vulnerability',
  phishing: 'Phishing',
  network: 'Network',
  webapp: 'Web App',
}

const AGENT_ICONS: Record<AgentKind, string> = {
  vulnerability: '🔍',
  phishing: '🎣',
  network: '🌐',
  webapp: '🕸️',
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso.slice(0, 16)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function groupIntoSessions(findings: Finding[]): ScanSession[] {
  const map = new Map<string, Finding[]>()
  for (const f of findings) {
    // Findings stamped with a run_id form one session per run, keeping every
    // agent's results for that run together instead of merging into whatever
    // else was scanned against the same target that day. Untagged findings
    // (e.g. imported scans) fall back to agent + asset + source + hour, so
    // scans from different times stay distinguishable.
    const key =
      f.run_id ??
      `${f.agent}::${f.asset ?? 'unknown'}::${f.source}::${f.detected_at.slice(0, 13)}`
    if (!map.has(key)) map.set(key, [])
    map.get(key)!.push(f)
  }

  return Array.from(map.entries())
    .map(([key, items]): ScanSession => {
      const first = items[0]!
      const isRun = first.run_id != null
      const severities: Record<Severity, number> = {
        critical: 0, high: 0, medium: 0, low: 0, info: 0,
      }
      for (const f of items) severities[f.severity] = (severities[f.severity] ?? 0) + 1

      const criticalCount = severities.critical
      const highCount = severities.high
      const status: ScanSession['status'] =
        criticalCount > 0 ? 'critical' : highCount > 0 ? 'warning' : 'clean'

      const sources = [...new Set(items.map((f) => f.source))]
      const timestamps = items.map((f) => f.detected_at).sort().reverse()
      const timestamp = timestamps[0] ?? first.detected_at

      return {
        id: key,
        agent: isRun ? ('run' as const) : (first.agent as AgentKind),
        asset: first.asset ?? 'unknown',
        source: sources.join(', '),
        date: formatTimestamp(timestamp),
        timestamp,
        findings: items,
        severities,
        criticalCount,
        highCount,
        status,
      }
    })
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
}

function SeverityPips({ severities }: { severities: Record<Severity, number> }) {
  return (
    <div className="flex flex-wrap gap-2">
      {SEVERITY_ORDER.map((sev) =>
        severities[sev] > 0 ? (
          <SeverityBadge key={sev} severity={sev} count={severities[sev]} size="sm" />
        ) : null,
      )}
    </div>
  )
}

function sessionIcon(session: ScanSession): string {
  return session.agent === 'run' ? '⚙️' : AGENT_ICONS[session.agent]
}

function sessionAgentLabel(session: ScanSession): string {
  if (session.agent !== 'run') return AGENT_LABELS[session.agent]
  const agents = [...new Set(session.findings.map((f) => f.agent))]
  return `Pipeline · ${agents.length} agent${agents.length === 1 ? '' : 's'}`
}

export default function ScansPage() {
  const [sessions, setSessions] = useState<ScanSession[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState<AgentKind | 'all'>('all')
  const [statusFilter, setStatusFilter] = useState<'all' | 'critical' | 'warning' | 'clean'>('all')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [view, setView] = useState<'recent' | 'previous'>('recent')

  useEffect(() => {
    let cancelled = false

    const loadAll = async () => {
      const all: Finding[] = []
      try {
        for (let offset = 0; ; offset += 200) {
          const page = await fetchFindings(200, offset)
          all.push(...page.items)
          if (offset + page.items.length >= page.total) break
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load scans')
        return
      }
      if (!cancelled) setSessions(groupIntoSessions(all))
    }

    loadAll()
    return () => { cancelled = true }
  }, [])

  const filtered = sessions?.filter((s) => {
    if (filter !== 'all' && !s.findings.some((f) => f.agent === filter)) return false
    if (statusFilter !== 'all' && s.status !== statusFilter) return false
    return true
  }) ?? []

  // "Recent" shows the newest RECENT_LIMIT sessions; "Previous" shows the rest.
  const RECENT_LIMIT = 10
  const recentSessions = filtered.slice(0, RECENT_LIMIT)
  const previousSessions = filtered.slice(RECENT_LIMIT)
  const visibleSessions = view === 'recent' ? recentSessions : previousSessions

  return (
    <main>
      {/* Header */}
      <div className="page-title">
        <div>
          <span className="eyebrow">History</span>
          <h1>Recent Scans</h1>
          <p className="subtitle">
            Each pipeline run or inbox scan is its own session, newest first.
          </p>
        </div>
        <Link href="/" className="btn btn-ghost">← Home</Link>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
        {(['all', 'vulnerability', 'phishing', 'network', 'webapp'] as const).map((a) => (
          <button
            key={a}
            className={`btn${filter === a ? ' btn-primary' : ''}`}
            onClick={() => setFilter(a)}
            style={{ textTransform: 'capitalize' }}
          >
            {a === 'all' ? 'All Agents' : AGENT_LABELS[a]}
          </button>
        ))}
        <div style={{ width: '1px', background: 'var(--border)', margin: '0 0.25rem' }} />
        {(['all', 'critical', 'warning', 'clean'] as const).map((s) => (
          <button
            key={s}
            className={`btn${statusFilter === s ? ' btn-primary' : ''}`}
            onClick={() => setStatusFilter(s)}
            style={{ textTransform: 'capitalize' }}
          >
            {s === 'all' ? 'All Statuses' : s}
          </button>
        ))}
        <div style={{ width: '1px', background: 'var(--border)', margin: '0 0.25rem' }} />
        {(['recent', 'previous'] as const).map((v) => (
          <button
            key={v}
            className={`btn${view === v ? ' btn-primary' : ''}`}
            onClick={() => { setView(v); setExpanded(null) }}
            style={{ textTransform: 'capitalize' }}
          >
            {v === 'recent' ? 'Recent scans' : 'Previous scans'}
          </button>
        ))}
      </div>

      {/* Summary row */}
      {sessions && (
        <div className="stat-grid" style={{ marginBottom: '1.5rem' }}>
          <div className="stat-card">
            <div className="label">Total Sessions</div>
            <div className="value">{visibleSessions.length}</div>
            <div className="sub">{view === 'recent' ? 'newest scans' : 'previous scans'}</div>
          </div>
          <div className="stat-card critical">
            <div className="label">Critical Sessions</div>
            <div className="value">{visibleSessions.filter((s) => s.status === 'critical').length}</div>
            <div className="sub">found critical findings</div>
          </div>
          <div className="stat-card high">
            <div className="label">Warning Sessions</div>
            <div className="value">{visibleSessions.filter((s) => s.status === 'warning').length}</div>
            <div className="sub">high severity only</div>
          </div>
          <div className="stat-card ok">
            <div className="label">Clean Sessions</div>
            <div className="value">{visibleSessions.filter((s) => s.status === 'clean').length}</div>
            <div className="sub">no critical/high findings</div>
          </div>
        </div>
      )}

      {/* Scan list */}
      <section className="panel" style={{ padding: '0' }}>
        {/* Table header */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '2fr 1.5fr 1fr 1fr 2fr 1.5fr',
            gap: '1rem',
            padding: '0.75rem 1.5rem',
            borderBottom: '1px solid var(--border)',
            fontSize: '0.7rem',
            fontWeight: 700,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            color: 'var(--faint)',
          }}
        >
          <span>Asset / Target</span>
          <span>Agent</span>
          <span>Source</span>
          <span>Timestamp</span>
          <span>Findings</span>
          <span>Status</span>
        </div>

        {error && (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--bad)' }}>{error}</div>
        )}

        {!error && sessions === null && (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--muted)' }}>
            Loading scans…
          </div>
        )}

        {!error && sessions !== null && visibleSessions.length === 0 && (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--muted)' }}>
            {view === 'recent'
              ? 'No scan sessions match the current filters.'
              : 'No previous scans yet. Run more scans to build up history.'}
          </div>
        )}

        {visibleSessions.map((session) => {
          const isExpanded = expanded === session.id
          const statusColor =
            session.status === 'critical'
              ? '#ef4444'
              : session.status === 'warning'
                ? '#f97316'
                : '#10b981'
          const statusLabel =
            session.status === 'critical'
              ? '● Critical'
              : session.status === 'warning'
                ? '● Warning'
                : '● Clean'

          return (
            <div key={session.id} style={{ borderBottom: '1px solid var(--border)' }}>
              {/* Row */}
              <button
                onClick={() => setExpanded(isExpanded ? null : session.id)}
                style={{
                  width: '100%',
                  display: 'grid',
                  gridTemplateColumns: '2fr 1.5fr 1fr 1fr 2fr 1.5fr',
                  gap: '1rem',
                  padding: '1rem 1.5rem',
                  background: isExpanded ? 'rgba(255,255,255,0.03)' : 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  textAlign: 'left',
                  color: 'var(--text)',
                  transition: 'background 0.2s ease',
                  alignItems: 'center',
                }}
              >
                {/* Asset */}
                <div style={{ minWidth: 0 }}>
                  <div
                    style={{
                      fontWeight: 600,
                      fontSize: '0.85rem',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      color: '#fff',
                    }}
                  >
                    {session.asset}
                  </div>
                </div>
                {/* Agent */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}>
                  <span>{sessionIcon(session)}</span>
                  <span>{sessionAgentLabel(session)}</span>
                </div>
                {/* Source */}
                <div style={{ fontSize: '0.78rem', color: 'var(--muted)' }}>
                  {session.source}
                </div>
                {/* Timestamp */}
                <div style={{ fontSize: '0.78rem', color: 'var(--muted)', whiteSpace: 'nowrap' }}>
                  {session.date}
                </div>
                {/* Findings */}
                <SeverityPips severities={session.severities} />
                {/* Status */}
                <div style={{ fontSize: '0.8rem', fontWeight: 700, color: statusColor }}>
                  {statusLabel}
                </div>
              </button>

              {/* Expanded findings */}
              {isExpanded && (
                <div
                  style={{
                    background: 'var(--bg)',
                    borderTop: '1px solid var(--border)',
                    padding: '1rem 1.5rem',
                  }}
                >
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--faint)', marginBottom: '0.75rem' }}>
                    Findings in this session ({session.findings.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {session.findings.map((f) => (
                      <Link
                        key={f.id}
                        href={`/findings/${f.id}`}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.75rem',
                          padding: '0.6rem 0.75rem',
                          borderRadius: '6px',
                          border: '1px solid var(--border)',
                          background: 'var(--panel)',
                          textDecoration: 'none',
                          color: 'var(--text)',
                          fontSize: '0.82rem',
                          transition: 'border-color 0.2s',
                        }}
                      >
                        <SeverityDot severity={f.severity} />
                        <span style={{ fontWeight: 600, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {f.title}
                        </span>
                        <span style={{ color: 'var(--muted)', fontSize: '0.75rem', textTransform: 'capitalize', flexShrink: 0 }}>
                          {f.severity}
                        </span>
                        <span style={{ color: 'var(--faint)', fontSize: '0.7rem', flexShrink: 0 }}>
                          ↗
                        </span>
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </section>
    </main>
  )
}
