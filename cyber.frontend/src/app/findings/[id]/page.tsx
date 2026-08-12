'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'

import { fetchFindingById, deleteFinding, verifyFindings } from '@/lib/api'
import { SeverityBadge } from '@/components/SeverityBadge'
import { CveList, FindingTypeChip } from '@/components/FindingTypeChip'
import { PriorityBreakdown } from '@/components/PriorityBreakdown'
import { StatusChip, VerificationHistory } from '@/components/VerificationHistory'
import {
  FINDING_TYPE_HINT,
  formatLocation,
  isRulesOnly,
  readPriority,
  readVerification,
} from '@/lib/findings'
import type { Finding } from '@/types'

/** Evidence is untrusted banner content. Read defensively and render as text. */
function evidenceString(finding: Finding, key: string): string | null {
  const value = finding.evidence?.[key]
  return typeof value === 'string' && value.trim() ? value : null
}

/**
 * How the finding was established, in one sentence.
 *
 * Worth stating plainly rather than leaving implicit: a rules-only finding means
 * no model was involved at all, which is a stronger claim than a model-written one,
 * not a weaker one.
 */
function provenance(finding: Finding): string {
  if (finding.agent !== 'vulnerability') return 'Produced by the ' + finding.agent + ' agent.'
  return isRulesOnly(finding)
    ? 'Established by the deterministic rule engine. No model was involved in this finding.'
    : 'Established by the deterministic rule engine, then written up by a model. The model cannot create a finding or a CVE id.'
}

export default function FindingDetailPage() {
  const params = useParams()
  const router = useRouter()
  const id = params.id as string

  const [finding, setFinding] = useState<Finding | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [deleting, setDeleting] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [verifyNote, setVerifyNote] = useState<string | null>(null)

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

  async function handleRecheck() {
    setVerifying(true)
    setVerifyNote(null)
    try {
      const response = await verifyFindings({ finding_ids: [id] })
      setVerifyNote(response.detail)
      // The re-check runs a scan out of band, so the result is not in this
      // response. Re-fetch once so a fast local scan shows up without a reload.
      setTimeout(() => {
        fetchFindingById(id).then(setFinding).catch(() => undefined)
      }, 4000)
    } catch (err) {
      setVerifyNote(err instanceof Error ? err.message : 'Could not queue a re-check.')
    } finally {
      setVerifying(false)
    }
  }

  const priority = finding ? readPriority(finding) : null
  const verification = finding ? readVerification(finding) : []
  const fact = finding ? evidenceString(finding, 'fact') : null
  const rationale = finding ? evidenceString(finding, 'rationale') : null
  const ruleId = finding ? evidenceString(finding, 'rule_id') : null

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
                <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', marginBottom: '0.5rem', flexWrap: 'wrap' }}>
                  <SeverityBadge severity={finding.severity} />
                  <FindingTypeChip type={finding.finding_type} />
                  <StatusChip status={finding.status} />
                  <span className={`agent-chip agent-${finding.agent}`}>{finding.agent}</span>
                </div>
                <h2 style={{ fontSize: '1.15rem', margin: 0 }}>{finding.title}</h2>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', flexShrink: 0 }}>
                <button
                  type="button"
                  className="btn"
                  onClick={handleRecheck}
                  disabled={verifying}
                  title="Re-scan this host and port to confirm whether the finding is fixed"
                >
                  {verifying ? 'Queueing…' : 'Re-check'}
                </button>
                <button
                  type="button"
                  className="btn btn-danger"
                  onClick={handleDelete}
                  disabled={deleting}
                >
                  {deleting ? 'Deleting…' : 'Delete'}
                </button>
              </div>
            </div>

            {verifyNote && (
              <p className="mt-3 mb-0 rounded-[10px] border border-border bg-bg-elev px-4 py-2 text-sm text-muted">
                {verifyNote}
              </p>
            )}

            <p className="mt-3 mb-0 text-xs text-faint">{FINDING_TYPE_HINT[finding.finding_type]}</p>

            <dl className="grid" style={{ marginTop: '1.25rem' }}>
              <dt>Asset</dt>
              <dd>{formatLocation(finding)}</dd>
              {finding.service && (
                <>
                  <dt>Service</dt>
                  <dd>{finding.service}</dd>
                </>
              )}
              {finding.cve_ids.length > 0 && (
                <>
                  <dt>CVEs</dt>
                  <dd>
                    <CveList cveIds={finding.cve_ids} />
                  </dd>
                </>
              )}
              <dt>Source</dt>
              <dd>{finding.source}</dd>
              <dt>Confidence</dt>
              <dd>{(finding.confidence * 100).toFixed(0)}%</dd>
              <dt>Status</dt>
              <dd>{finding.status.replace(/_/g, ' ')}</dd>
              <dt>Detected</dt>
              <dd>{new Date(finding.detected_at).toLocaleString()}</dd>
            </dl>

            {priority && (
              <>
                <hr className="sep" />
                <PriorityBreakdown priority={priority} />
              </>
            )}

            <hr className="sep" />

            <h3>Description</h3>
            <p style={{ whiteSpace: 'pre-wrap', color: 'var(--muted)' }}>{finding.description}</p>

            {fact && (
              <>
                <h3>What was observed</h3>
                <p className="font-mono text-[0.85rem] whitespace-pre-wrap text-muted">{fact}</p>
              </>
            )}

            {rationale && (
              <>
                <h3>Why it matters</h3>
                <p style={{ whiteSpace: 'pre-wrap', color: 'var(--muted)' }}>{rationale}</p>
              </>
            )}

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

            <h3 style={{ marginTop: '1.4rem' }}>Verification</h3>
            <VerificationHistory entries={verification} />

            <h3 style={{ marginTop: '1.4rem' }}>Provenance</h3>
            <p className="text-sm text-muted">
              {provenance(finding)}
              {ruleId && (
                <>
                  {' '}
                  Rule <code>{ruleId}</code>.
                </>
              )}
            </p>

            {/* Collapsed: everything above is drawn from this, and the raw blob is
                for when an analyst needs the parts the page does not model yet. */}
            <details className="mt-4">
              <summary className="cursor-pointer text-sm text-muted select-none hover:text-text">
                Raw evidence
              </summary>
              <pre
                style={{
                  overflowX: 'auto',
                  background: 'var(--bg-elev)',
                  border: '1px solid var(--border)',
                  padding: '1rem',
                  borderRadius: 10,
                  fontSize: '0.8rem',
                  color: 'var(--muted)',
                  marginTop: '0.75rem',
                }}
              >
                {JSON.stringify(finding.evidence, null, 2)}
              </pre>
            </details>

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
