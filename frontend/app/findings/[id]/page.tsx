'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'

import { fetchFindingById, deleteFinding } from '@/lib/api'
import type { Finding } from '@/lib/types'

const SEVERITY_LABEL: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

export default function FindingDetailPage() {
  const params = useParams()
  const router = useRouter()
  const id = params.id as string

  const [finding, setFinding] = useState<Finding | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [deleting, setDeleting] = useState(false)

  useEffect(() => {
    fetchFindingById(id)
      .then(setFinding)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [id])

  async function handleDelete() {
    if (!confirm('Are you sure you want to delete this finding?')) return

    setDeleting(true)
    try {
      await deleteFinding(id)
      router.push('/findings')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unknown error')
      setDeleting(false)
    }
  }

  return (
    <main>
      <div className="page-title">
        <div>
          <span className="eyebrow">Finding</span>
          <h1>Detection Details</h1>
          <p className="subtitle">
            <Link href="/findings" style={{ fontWeight: 700 }}>
              ← Back to Findings
            </Link>
          </p>
        </div>
      </div>

      <section className="panel">
        {loading && <span className="status pending">Loading…</span>}

        {error && (
          <div className="error">
            <span className="status bad">● Error</span>
            <p>{error}</p>
          </div>
        )}

        {finding && (
          <>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                gap: '1rem',
              }}
            >
              <div style={{ minWidth: 0 }}>
                <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span className={`badge sev-${finding.severity}`}>
                    {SEVERITY_LABEL[finding.severity] ?? finding.severity}
                  </span>
                  <span className={`agent-chip agent-${finding.agent}`}>{finding.agent}</span>
                </div>
                <h2 style={{ fontSize: '1.15rem', margin: 0 }}>{finding.title}</h2>
              </div>
              <button type="button" className="btn btn-danger" onClick={handleDelete} disabled={deleting}>
                {deleting ? 'Deleting…' : 'Delete'}
              </button>
            </div>

            <dl className="grid" style={{ marginTop: '1.25rem' }}>
              <dt>Asset</dt>
              <dd>{finding.asset || 'N/A'}</dd>
              <dt>Source</dt>
              <dd>{finding.source}</dd>
              <dt>Confidence</dt>
              <dd>{(finding.confidence * 100).toFixed(0)}%</dd>
              <dt>Detected</dt>
              <dd>{new Date(finding.detected_at).toLocaleString()}</dd>
            </dl>

            <hr className="sep" />

            <h3>Description</h3>
            <p style={{ whiteSpace: 'pre-wrap', color: 'var(--muted)' }}>{finding.description}</p>

            {finding.recommendation && (
              <>
                <h3>Recommendation</h3>
                <div style={{ background: 'rgba(52,211,153,0.06)', border: '1px solid rgba(52,211,153,0.25)', borderRadius: 10, padding: '0.9rem 1rem' }}>
                  <p style={{ whiteSpace: 'pre-wrap', margin: 0, color: 'var(--text)' }}>
                    {finding.recommendation}
                  </p>
                </div>
              </>
            )}

            <h3 style={{ marginTop: '1.4rem' }}>Evidence</h3>
            <pre
              style={{
                overflowX: 'auto',
                background: 'var(--bg-elev)',
                border: '1px solid var(--border)',
                padding: '1rem',
                borderRadius: 10,
                fontSize: '0.8rem',
                color: 'var(--muted)',
              }}
            >
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>

            {finding.raw_reference && (
              <p style={{ fontSize: '0.8rem', color: 'var(--faint)', marginTop: '0.9rem' }}>
                Raw reference: <code>{finding.raw_reference}</code>
              </p>
            )}
          </>
        )}
      </section>
    </main>
  )
}
