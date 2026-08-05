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

// All detection agents that share the same pipeline (MVP)
const AGENTS: AgentKind[] = ['vulnerability', 'phishing', 'network', 'webapp']

export default function RunPipelinePage() {
  // UI input state
  const [source, setSource] = useState('manual')
  const [asset, setAsset] = useState('')
  const [rawInput, setRawInput] = useState('')
  const [background, setBackground] = useState(false) // kept for compatibility, but pipeline runs inline to collect findings

  // UI state for request/response handling
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<AgentRunResponse[] | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      // Run the full pipeline: invoke each agent sequentially (parallel via Promise.all)
      const responses = await Promise.all(
        AGENTS.map((a) =>
          runAgent(a, {
            source,
            asset: asset || undefined,
            raw_input: rawInput,
            // For a full pipeline we want immediate results, so force inline mode.
            background: false,
            persist: true,
          })
        )
      )
      setResults(responses)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main>
      <div className="page-title">
        <div>
          <span className="eyebrow">Agent Execution</span>
          <h1>Run Pipeline</h1>
          <p className="subtitle">Feed an artifact and run the full detection pipeline.</p>
        </div>
        <Link href="/" className="btn btn-ghost">
          ← Home
        </Link>
      </div>

      <div className="grid-2">
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <section className="panel" style={{ margin: 0 }}>
            <h2>Configuration</h2>

            {/* Source Tool */}
            <div style={{ marginBottom: '1rem' }}>
              <label className="field" htmlFor="source">
                Source Tool
              </label>
              <input
                id="source"
                type="text"
                value={source}
                onChange={(e) => setSource(e.target.value)}
                placeholder="nmap, zap, trivy, mailparser…"
                required
              />
            </div>

            {/* Target Asset */}
            <div style={{ marginBottom: '1rem' }}>
              <label className="field" htmlFor="asset">
                Target Asset
              </label>
              <input
                id="asset"
                type="text"
                value={asset}
                onChange={(e) => setAsset(e.target.value)}
                placeholder="https://target.example.com (optional)"
              />
            </div>

            {/* Raw Input Data */}
            <div style={{ marginBottom: '1rem' }}>
              <label className="field" htmlFor="rawInput">
                Raw Input Data
              </label>
              <textarea
                id="rawInput"
                value={rawInput}
                onChange={(e) => setRawInput(e.target.value)}
                required
                rows={9}
                placeholder="Paste a scan result, email, log excerpt, or HTTP response…"
                style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}
              />
            </div>

            {/* Background option – retained for UI consistency but ignored by pipeline */}
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.9rem' }}>
              <input
                type="checkbox"
                checked={background}
                onChange={(e) => setBackground(e.target.checked)}
                style={{ width: 'auto' }}
              />
              Run in background (via queue) – not used for full pipeline runs
            </label>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading}
              style={{ width: '100%', marginTop: '1.1rem' }}
            >
              {loading ? 'Analyzing…' : 'Run Full Pipeline'}
            </button>
          </section>
        </form>

        <section className="panel" style={{ margin: 0, alignSelf: 'start' }}>
          <h2>Result</h2>

          {error && (
            <div>
              <span className="status bad">● Error</span>
              <p className="error">{error}</p>
            </div>
          )}

          {results && (
            <div>
              <span className="pill ok">
                <span className="dot" />
                Success
              </span>
              {/* Aggregate all findings from the pipeline */}
              {(() => {
                // Flatten findings across all agents
                const allFindings: Finding[] = results.flatMap((r) => r.findings ?? [])
                return (
                  <>
                    <p style={{ marginTop: '1rem' }}>
                      Total Findings: <strong>{allFindings.length}</strong>
                    </p>
                    {allFindings.length > 0 && (
                      <div style={{ marginTop: '0.75rem' }}>
                        {allFindings.map((f) => (
                          <Link
                            key={f.id}
                            href={`/findings/${f.id}`}
                            className="finding-row"
                            style={{ border: '1px solid var(--border)' }}
                          >
                            <span className={`badge sev-${f.severity}`}>{SEVERITY_LABEL[f.severity] ?? f.severity}</span>
                            <div className="meta">
                              <div className="title">{f.title}</div>
                              <div className="sub">{f.asset ?? f.source}</div>
                            </div>
                          </Link>
                        ))}
                      </div>
                    )}
                  </>
                )
              })()}
            </div>
          )}

          {!results && !error && (
            <p style={{ color: 'var(--faint)', margin: 0, fontSize: '0.9rem' }}>
              Submitted pipeline runs will appear here.
            </p>
          )}
        </section>
      </div>
    </main>
  )
}
