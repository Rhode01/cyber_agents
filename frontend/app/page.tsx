'use client'

import { useEffect, useState } from 'react'

import { BACKEND_URL, fetchBackendHealth } from '@/lib/api'
import type { BackendHealth } from '@/lib/types'

type State =
  | { kind: 'loading' }
  | { kind: 'ok'; health: BackendHealth }
  | { kind: 'error'; message: string }

const MODULES = [
  ['frontend', 'localhost:3000'],
  ['backend', 'localhost:8000'],
  ['ai.engine', 'localhost:8003'],
  ['mcpserver', 'localhost:8004'],
  ['postgres', 'localhost:5432'],
  ['redis', 'localhost:6379'],
] as const

export default function Home() {
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [attempt, setAttempt] = useState(0)

  // setState happens in the promise callbacks, never synchronously in the effect
  // body - that is what react-hooks/set-state-in-effect guards against.
  useEffect(() => {
    let cancelled = false

    fetchBackendHealth()
      .then((health) => {
        if (!cancelled) setState({ kind: 'ok', health })
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({
            kind: 'error',
            message: error instanceof Error ? error.message : 'Unknown error',
          })
        }
      })

    return () => {
      cancelled = true
    }
  }, [attempt])

  // Safe from an event handler, which is not an effect. Bumping `attempt`
  // re-runs the effect above.
  function check() {
    setState({ kind: 'loading' })
    setAttempt((n) => n + 1)
  }

  return (
    <main>
      <h1>Cybersecurity Agents Platform</h1>
      <p className="subtitle">
        Phase 1 scaffold. This page exists to prove the frontend can reach the backend.
      </p>

      <section className="panel">
        <h2>Backend health</h2>

        {state.kind === 'loading' && <span className="status pending">checking…</span>}

        {state.kind === 'ok' && (
          <>
            <span className="status ok">● reachable</span>
            <dl>
              <dt>Endpoint</dt>
              <dd>
                <code>GET {BACKEND_URL}/health</code>
              </dd>
              <dt>Status</dt>
              <dd>{state.health.status}</dd>
              <dt>Service</dt>
              <dd>{state.health.service}</dd>
              <dt>Version</dt>
              <dd>{state.health.version}</dd>
              <dt>Environment</dt>
              <dd>{state.health.app_env}</dd>
            </dl>
          </>
        )}

        {state.kind === 'error' && (
          <>
            <span className="status bad">● unreachable</span>
            <p className="error">{state.message}</p>
            <p className="error">
              Start it with <code>make up</code> or <code>make dev-backend</code>.
            </p>
          </>
        )}

        <p style={{ marginTop: '1.1rem', marginBottom: 0 }}>
          <button type="button" onClick={check}>
            Check again
          </button>
        </p>
      </section>

      <section className="panel">
        <h2>Module map</h2>
        <ul className="ports">
          {MODULES.map(([name, address]) => (
            <li key={name}>
              <span>{name}</span>
              <span>{address}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="panel">
        <h2>Deferred to later phases</h2>
        <p style={{ margin: 0, fontSize: '0.9rem', color: 'var(--muted)' }}>
          Detection logic, live LLM reasoning, MCP tools, the correlation engine, authentication,
          threat-intel enrichment, and the analyst dashboard.
        </p>
      </section>
    </main>
  )
}
