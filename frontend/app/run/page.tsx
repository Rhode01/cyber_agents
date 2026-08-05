'use client'

import { useState } from 'react'
import Link from 'next/link'

import { runAgent } from '@/lib/api'
import type { AgentKind, Finding, AgentRunResponse } from '@/lib/types'

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

type AgentState =
  | { state: 'pending'; findings: [] }
  | { state: 'running'; findings: [] }
  | { state: 'done'; findings: Finding[]; source?: string }
  | { state: 'error'; findings: []; error: string }

function statusLabel(status: AgentState): string {
  switch (status.state) {
    case 'running':
      return 'Scanning…'
    case 'done':
      return `${status.findings.length} finding${status.findings.length === 1 ? '' : 's'}`
    case 'error':
      return 'Scan failed'
    default:
      return 'Queued'
  }
}

export default function RunPipelinePage() {
  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [statuses, setStatuses] = useState<Record<AgentKind, AgentState> | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const clean = target.trim()
    if (!clean) return

    setLoading(true)
    setError(null)

    const initial: Record<AgentKind, AgentState> = {
      vulnerability: { state: 'running', findings: [] },
      phishing: { state: 'running', findings: [] },
      network: { state: 'running', findings: [] },
      webapp: { state: 'running', findings: [] },
    }
    setStatuses(initial)

    // Launch the whole pipeline: every agent scans the same target itself.
    await Promise.all(
      AGENTS.map(async ({ kind }) => {
        try {
          const response: AgentRunResponse = await runAgent(kind, {
            source: 'auto',
            asset: clean,
            raw_input: '',
            background: false,
            persist: true,
          })
          setStatuses((prev) =>
            prev
              ? {
                  ...prev,
                  [kind]: {
                    state: 'done',
                    findings: response.findings ?? [],
                    source: response.findings?.[0]?.source,
                  },
                }
              : prev,
          )
        } catch (err: unknown) {
          setStatuses((prev) =>
            prev
              ? {
                  ...prev,
                  [kind]: {
                    state: 'error',
                    findings: [],
                    error: err instanceof Error ? err.message : 'Unknown error',
                  },
                }
              : prev,
          )
        }
      }),
    )

    setLoading(false)
  }

  const allFindings: Finding[] = Object.values(statuses ?? {}).flatMap((s) => s.findings)
  const anyFailed = Object.values(statuses ?? {}).some((s) => s.state === 'error')

  return (
    <main>
      <div className="page-title">
        <div>
          <span className="eyebrow">Agent Execution</span>
          <h1>Run Agent</h1>
          <p className="subtitle">
            Enter a target — the AI launches every scan in the pipeline itself.
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
            <ul className="ports" style={{ margin: 0 }}>
              {AGENTS.map((agent) => (
                <li key={agent.kind}>
                  <span style={{ fontWeight: 600, textTransform: 'none' }}>{agent.name}</span>
                  <span style={{ color: 'var(--muted)', fontSize: '0.85rem' }}>{agent.tool}</span>
                </li>
              ))}
            </ul>
          </section>
        </form>

        <section className="panel" style={{ margin: 0, alignSelf: 'start' }}>
          <h2>Run Status</h2>

          {error && (
            <div>
              <span className="status bad">● Error</span>
              <p className="error">{error}</p>
            </div>
          )}

          {!statuses && !error && (
            <p style={{ color: 'var(--faint)', margin: 0, fontSize: '0.9rem' }}>
              Enter a target and press Run Agent to launch the full pipeline.
            </p>
          )}

          {statuses && (
            <>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                {AGENTS.map((agent) => {
                  const status = statuses[agent.kind]
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
                        {status.state === 'pending' && <span className="status pending">○</span>}
                        <div style={{ minWidth: 0 }}>
                          <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{agent.name}</div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--muted)' }}>
                            {agent.tool} — {statusLabel(status)}
                          </div>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>

              {!loading && (
                <div style={{ marginTop: '1rem', display: 'flex', gap: '0.75rem' }}>
                  <span className={`pill ${anyFailed ? 'bad' : 'ok'}`}>
                    <span className="dot" />
                    Pipeline {anyFailed ? 'completed with errors' : 'complete'}
                  </span>
                </div>
              )}

              <p style={{ marginTop: '1rem' }}>
                Total Findings: <strong>{allFindings.length}</strong>
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
