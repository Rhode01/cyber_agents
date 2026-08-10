'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import Link from 'next/link'

import {
  createRun,
  fetchLatestRun,
  fetchSettings,
  runAgent,
  runDiscovery,
  updateRun,
} from '@/lib/api'
import type {
  AgentKind,
  AgentStatusSnapshot,
  DiscoveryReport,
  Finding,
  AgentRunResponse,
  PipelineMode,
  RunRead,
  RunStatus,
  RunUpdate,
} from '@/lib/types'

const SEVERITY_LABEL: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

interface AgentDef {
  kind: AgentKind
  name: string
  tool: string
  description: string
}

// All four detection agents share the same MVP pipeline. Clicking "Run Agent"
// launches the whole pipeline: each agent scans the target itself.
const AGENTS: AgentDef[] = [
  {
    kind: 'vulnerability',
    name: 'Vulnerability Assessment',
    tool: 'nmap',
    description: 'Scans the host and correlates open services with known CVEs.',
  },
  {
    kind: 'webapp',
    name: 'Web Application (OWASP Top 10)',
    tool: 'nuclei',
    description: 'Scans the URL and maps alerts onto the OWASP Top 10.',
  },
  {
    kind: 'network',
    name: 'Network Traffic Analysis',
    tool: 'ss snapshot',
    description: 'Takes a live TCP snapshot and looks for anomalies.',
  },
  {
    kind: 'phishing',
    name: 'Phishing Detection',
    tool: 'DNS + HTTP checks',
    description: 'Runs SPF/DKIM/DMARC and URL checks against the target.',
  },
]

const EMPTY_STATUSES: Record<AgentKind, AgentStatusSnapshot> = {
  vulnerability: { state: 'pending', count: 0 },
  phishing: { state: 'pending', count: 0 },
  network: { state: 'pending', count: 0 },
  webapp: { state: 'pending', count: 0 },
}

function statusLabel(status: AgentStatusSnapshot): string {
  switch (status.state) {
    case 'running':
      return 'Scanning…'
    case 'done':
      return `${status.count} finding${status.count === 1 ? '' : 's'}`
    case 'error':
      return 'Scan failed'
    case 'skipped':
      return 'Skipped'
    default:
      return 'Queued'
  }
}

function statusText(status: AgentStatusSnapshot): string | null {
  if (status.state === 'error') return status.error ?? 'Unknown error'
  return null
}

function parsePipelineAgents(raw: string | undefined): AgentKind[] {
  if (!raw) return []
  try {
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter((a): a is AgentKind => AGENTS.some((d) => d.kind === a))
  } catch {
    return []
  }
}

export default function RunPipelinePage() {
  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [statuses, setStatuses] = useState<Record<AgentKind, AgentStatusSnapshot> | null>(null)
  const [findingsByAgent, setFindingsByAgent] = useState<Record<AgentKind, Finding[]>>({
    vulnerability: [],
    phishing: [],
    network: [],
    webapp: [],
  })
  const [discovery, setDiscovery] = useState<DiscoveryReport | null>(null)
  const [discoveryError, setDiscoveryError] = useState<string | null>(null)
  const [runId, setRunId] = useState<string | null>(null)
  const runIdRef = useRef<string | null>(null)
  const [runStatus, setRunStatus] = useState<RunStatus | null>(null)
  const [restored, setRestored] = useState(false)
  const [pipelineMode, setPipelineMode] = useState<PipelineMode>('auto')
  const [pipelineAgents, setPipelineAgents] = useState<AgentKind[]>([])
  const [mailSource, setMailSource] = useState('')

  const persist = useCallback((patch: RunUpdate) => {
    const id = runIdRef.current
    if (!id) return
    updateRun(id, patch).catch(() => {
      // Persistence is best-effort: the page still works if a PATCH is lost.
    })
  }, [])

  const restoreRun = useCallback((run: RunRead) => {
    runIdRef.current = run.id
    setRunId(run.id)
    setRunStatus(run.status)
    setTarget(run.target)
    setPipelineMode(run.mode)
    setDiscovery(run.discovery)
    setStatuses(run.agent_statuses)
    setFindingsByAgent({
      vulnerability: [],
      phishing: [],
      network: [],
      webapp: [],
    })
    setRestored(true)
  }, [])

  useEffect(() => {
    let cancelled = false

    fetchSettings()
      .then((data) => {
        if (cancelled) return
        const map: Record<string, string> = {}
        data.forEach(s => (map[s.key] = s.value))
        setPipelineMode(map['pipeline_mode'] === 'manual' ? 'manual' : 'auto')
        setPipelineAgents(parsePipelineAgents(map['pipeline_agents']))
        setMailSource(map['mail_source'] || '')
      })
      .catch(() => {})

    fetchLatestRun()
      .then((run) => {
        if (!cancelled) restoreRun(run)
      })
      .catch(() => {})

    return () => {
      cancelled = true
    }
  }, [restoreRun])

  const agentsToRun = useCallback((): AgentDef[] => {
    if (pipelineMode === 'manual') {
      return AGENTS.filter((a) => pipelineAgents.includes(a.kind))
    }
    // Auto mode: full pipeline, but skip anything unconfigured.
    const hasMail = mailSource.trim().length > 0
    return AGENTS.filter((a) => a.kind !== 'phishing' || hasMail)
  }, [pipelineMode, pipelineAgents, mailSource])

  const setAgentStatus = useCallback((kind: AgentKind, snapshot: AgentStatusSnapshot) => {
    setStatuses((prev) => {
      if (!prev) return prev
      const next = { ...prev, [kind]: snapshot }
      persist({ agent_statuses: next })
      return next
    })
  }, [persist])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const clean = target.trim()
    if (!clean || loading) return

    setLoading(true)
    setError(null)
    setDiscoveryError(null)
    setDiscovery(null)
    setRestored(false)
    setFindingsByAgent({ vulnerability: [], phishing: [], network: [], webapp: [] })

    let currentRunId: string | null
    try {
      const run = await createRun({ target: clean, mode: pipelineMode })
      currentRunId = run.id
      runIdRef.current = currentRunId
      setRunId(currentRunId)
      setRunStatus('running')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Could not create run')
      setLoading(false)
      return
    }

    setStatuses(EMPTY_STATUSES)
    persist({ agent_statuses: EMPTY_STATUSES })

    try {
      // Phase 1: discovery — enumerate networks and find web services.
      const report = await runDiscovery()
      setDiscovery(report)
      persist({ discovery: report })
    } catch (err: unknown) {
      setDiscoveryError(err instanceof Error ? err.message : 'Discovery failed')
    }

    const selected = agentsToRun()
    const picked = selected.map((a) => a.kind)
    const next: Record<AgentKind, AgentStatusSnapshot> = { ...EMPTY_STATUSES }
    for (const kind of AGENTS.map((a) => a.kind)) {
      next[kind] = picked.includes(kind)
        ? { state: 'running', count: 0 }
        : { state: 'skipped', count: 0 }
    }
    setStatuses(next)
    persist({ agent_statuses: next })

    // Phase 2: launch each selected agent against the target.
    const results = await Promise.all(
      selected.map(async ({ kind }) => {
        try {
          const response: AgentRunResponse = await runAgent(kind, {
            source: 'auto',
            asset: clean,
            raw_input: '',
            background: false,
            persist: true,
            run_id: currentRunId ?? undefined,
          })
          const findings = response.findings ?? []
          return { kind, ok: true as const, findings }
        } catch (err: unknown) {
          return {
            kind,
            ok: false as const,
            error: err instanceof Error ? err.message : 'Unknown error',
          }
        }
      }),
    )

    for (const result of results) {
      if (result.ok) {
        setFindingsByAgent((prev) => ({ ...prev, [result.kind]: result.findings }))
        setAgentStatus(result.kind, { state: 'done', count: result.findings.length })
      } else {
        setAgentStatus(result.kind, { state: 'error', count: 0, error: result.error })
      }
    }

    const anyFailed = results.some((r) => !r.ok)
    const final: RunStatus = anyFailed ? 'completed_with_errors' : 'completed'
    setRunStatus(final)
    persist({ status: final })

    setLoading(false)
  }

  const allFindings: Finding[] = Object.values(findingsByAgent).flat()
  const totalFindings = Object.values(statuses ?? {}).reduce((n, s) => n + s.count, 0)
  const anyFailed = Object.values(statuses ?? {}).some((s) => s.state === 'error')
  const selectedCount = agentsToRun().length
  const skippedAgents = AGENTS.filter((a) => !agentsToRun().some((s) => s.kind === a.kind))

  return (
    <main>
      <div className="page-title">
        <div>
          <span className="eyebrow">Agent Execution</span>
          <h1>Run Agent</h1>
          <p className="subtitle">
            Enter a target — discovery maps the network, then the pipeline runs the selected agents.
          </p>
        </div>
        <Link href="/" className="btn btn-ghost">
          ← Home
        </Link>
      </div>

      <div className="grid-2">
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <section className="panel" style={{ margin: 0 }}>
            <h2>Target</h2>
            <p style={{ color: 'var(--muted)', fontSize: '0.9rem', margin: '0 0 1rem' }}>
              The agents scan it automatically — no raw scanner output to paste. Accepts a host,
              IP, URL, or domain (e.g. <code>10.0.0.20</code> or{' '}
              <code>https://app.example.com</code>).
            </p>

            <div style={{ marginBottom: '1rem' }}>
              <label className="field" htmlFor="target">
                Target Asset
              </label>
              <input
                id="target"
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="host, IP, URL, or domain"
                required
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading || !target.trim()}
              style={{ width: '100%', marginTop: '0.4rem' }}
            >
              {loading ? 'Running pipeline…' : '▶ Run Agent'}
            </button>
          </section>

          <section className="panel" style={{ margin: 0 }}>
            <h2>Pipeline</h2>
            <p style={{ fontSize: '0.85rem', color: 'var(--muted)', margin: '0 0 0.75rem' }}>
              Mode:{' '}
              <strong>
                {pipelineMode === 'manual'
                  ? `Manual — ${selectedCount} selected`
                  : 'Auto — full pipeline, skip unconnected'}
              </strong>
            </p>
            <ul className="ports" style={{ margin: 0 }}>
              {AGENTS.map((agent) => {
                const skipped = !agentsToRun().some((a) => a.kind === agent.kind)
                return (
                  <li key={agent.kind}>
                    <span
                      style={{
                        fontWeight: 600,
                        textTransform: 'none',
                        ...(skipped ? { color: 'var(--faint)', textDecoration: 'line-through' } : {}),
                      }}
                    >
                      {agent.name}
                    </span>
                    <span style={{ color: 'var(--muted)', fontSize: '0.85rem' }}>
                      {skipped ? 'skipped' : agent.tool}
                    </span>
                  </li>
                )
              })}
            </ul>
            {skippedAgents.length > 0 && (
              <p style={{ fontSize: '0.78rem', color: 'var(--faint)', margin: '0.5rem 0 0' }}>
                Skipped: {skippedAgents.map((a) => a.name).join(', ')}
              </p>
            )}
          </section>
        </form>

        <section className="panel" style={{ margin: 0, alignSelf: 'start' }}>
          <h2>Run Status</h2>

          {restored && runId && (
            <p style={{ fontSize: '0.8rem', color: 'var(--faint)', margin: '0 0 0.75rem' }}>
              Restored from run <code>{runId.slice(0, 8)}</code> — status persists across refreshes.
            </p>
          )}

          {error && (
            <div>
              <span className="status bad">● Error</span>
              <p className="error">{error}</p>
            </div>
          )}

          {!statuses && !error && (
            <p style={{ color: 'var(--faint)', margin: 0, fontSize: '0.9rem' }}>
              Enter a target and press Run Agent to run discovery and launch the pipeline.
            </p>
          )}

          {discoveryError && (
            <div style={{ marginBottom: '1rem' }}>
              <span className="status bad">● Discovery failed</span>
              <p className="error" style={{ margin: '0.25rem 0 0' }}>{discoveryError}</p>
            </div>
          )}

          {discovery && (
            <div
              style={{
                marginBottom: '1rem',
                padding: '0.6rem 0.75rem',
                borderRadius: '8px',
                border: '1px solid var(--border)',
                background: 'var(--bg-elev)',
              }}
            >
              <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                Discovery — this device: {discovery.web_hosts.length} web
                service{discovery.web_hosts.length === 1 ? '' : 's'} on{' '}
                {discovery.live_hosts.length} address
                {discovery.live_hosts.length === 1 ? '' : 'es'}
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--muted)', marginTop: '0.3rem' }}>
                {discovery.web_hosts.length > 0
                  ? discovery.web_hosts
                      .map((w) => `${w.host}${w.urls.length ? ' — ' + w.urls.join(', ') : ''}`)
                      .join(' · ')
                  : 'No web services probed. Run the agents against your target.'}
              </div>
            </div>
          )}

          {statuses && (
            <>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                {AGENTS.map((agent) => {
                  const status = statuses[agent.kind]
                  const detail = statusText(status)
                  return (
                    <div
                      key={agent.kind}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        gap: '0.75rem',
                        padding: '0.6rem 0.75rem',
                        borderRadius: '8px',
                        border: '1px solid var(--border)',
                        background: 'var(--bg-elev)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', minWidth: 0 }}>
                        {status.state === 'running' && (
                          <span className="status pending">●</span>
                        )}
                        {status.state === 'done' && (
                          <span className="pill ok">
                            <span className="dot" />
                          </span>
                        )}
                        {status.state === 'error' && <span className="status bad">●</span>}
                        {(status.state === 'skipped' || status.state === 'pending') && (
                          <span className="status pending">○</span>
                        )}
                        <div style={{ minWidth: 0 }}>
                          <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{agent.name}</div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--muted)' }}>
                            {agent.tool} — {statusLabel(status)}
                            {detail && <span style={{ color: 'var(--bad)' }}> · {detail}</span>}
                          </div>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>

              {runStatus && (
                <div style={{ marginTop: '1rem', display: 'flex', gap: '0.75rem' }}>
                  <span
                    className={`pill ${runStatus === 'running' ? 'pending' : anyFailed ? 'bad' : 'ok'}`}
                  >
                    <span className="dot" />
                    {runStatus === 'running'
                      ? 'Running…'
                      : `Pipeline ${runStatus === 'completed_with_errors' ? 'completed with errors' : 'complete'}`}
                  </span>
                  {!loading && runStatus !== 'running' && totalFindings > 0 && (
                    <Link href="/findings" className="btn btn-ghost" style={{ padding: '0.25rem 0.6rem' }}>
                      View findings →
                    </Link>
                  )}
                </div>
              )}

              <p style={{ marginTop: '1rem' }}>
                Total Findings: <strong>{totalFindings}</strong>
              </p>

              {allFindings.length > 0 && (
                <div style={{ marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {allFindings.map((f) => (
                    <Link
                      key={f.id}
                      href={`/findings/${f.id}`}
                      className="finding-row"
                      style={{ border: '1px solid var(--border)' }}
                    >
                      <span className={`badge sev-${f.severity}`}>
                        {SEVERITY_LABEL[f.severity] ?? f.severity}
                      </span>
                      <div className="meta">
                        <div className="title">{f.title}</div>
                        <div className="sub">{f.asset ?? f.source}</div>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </>
          )}
        </section>
      </div>
    </main>
  )
}
