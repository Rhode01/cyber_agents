'use client'

/**
 * The page that closes the loop: submit a message, watch it analyse, read the verdict.
 *
 * Polling obeys `react-hooks/set-state-in-effect` - `setState` happens only inside
 * promise callbacks, never synchronously in an effect body, with a `cancelled` flag on
 * cleanup. That lint rule already caught this pattern once in this project.
 *
 * Every value taken from a message or a finding is rendered as text. The subject, the
 * sender, the indicator facts and the model's explanation all derive from attacker-
 * authored input, so `dangerouslySetInnerHTML` must not appear anywhere in this file.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import IndicatorList from '@/components/IndicatorList'
import IntakeProgress from '@/components/IntakeProgress'
import VerdictBadge from '@/components/VerdictBadge'
import { SeverityBadge } from '@/components/SeverityBadge'
import {
  IntakeError,
  fetchMessage,
  fetchMessageFindings,
  fetchMessages,
  submitUrl,
  uploadMessage,
} from '@/lib/intake'
import { TERMINAL_STATUSES } from '@/types/intake'
import type { Indicator, Message } from '@/types/intake'
import type { Finding, Severity } from '@/types'

const POLL_INTERVAL_MS = 2000
const MAX_POLL_ATTEMPTS = 60 // ~2 minutes, then stop and say so rather than spin forever

type Mode = 'file' | 'url'

function indicatorsOf(finding: Finding): Indicator[] {
  const raw = (finding.evidence as Record<string, unknown>)?.indicators
  return Array.isArray(raw) ? (raw as Indicator[]) : []
}

function verdictOf(finding: Finding): string {
  const raw = (finding.evidence as Record<string, unknown>)?.verdict
  return typeof raw === 'string' ? raw : ''
}

export default function PhishingPage() {
  const [mode, setMode] = useState<Mode>('file')
  const [file, setFile] = useState<File | null>(null)
  const [url, setUrl] = useState('')
  const [enrich, setEnrich] = useState(false)

  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<Message | null>(null)
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [timedOut, setTimedOut] = useState(false)
  const [history, setHistory] = useState<Message[]>([])

  const fileInput = useRef<HTMLInputElement>(null)

  const loadHistory = useCallback(() => {
    fetchMessages({ limit: 8 })
      .then((page) => setHistory(page.items))
      .catch(() => setHistory([]))
  }, [])

  useEffect(() => {
    loadHistory()
  }, [loadHistory])

  // Poll the intake row until it reaches a terminal status, then load its findings.
  useEffect(() => {
    if (message === null) return
    if (TERMINAL_STATUSES.includes(message.status)) return

    let cancelled = false
    let attempts = 0

    const tick = () => {
      fetchMessage(message.id)
        .then((latest) => {
          if (cancelled) return
          setMessage(latest)
          attempts += 1
          if (!TERMINAL_STATUSES.includes(latest.status) && attempts >= MAX_POLL_ATTEMPTS) {
            setTimedOut(true)
          }
        })
        .catch((err: unknown) => {
          if (cancelled) return
          setError(err instanceof Error ? err.message : 'Lost contact with the backend')
        })
    }

    const timer = setInterval(tick, POLL_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [message])

  // Once analysis finishes, fetch what it produced.
  useEffect(() => {
    if (message === null || message.status !== 'completed') return

    let cancelled = false
    fetchMessageFindings(message.id)
      .then((page) => {
        if (!cancelled) setFindings(page.items)
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Could not load the findings')
        }
      })

    loadHistory()
    return () => {
      cancelled = true
    }
  }, [message, loadHistory])

  const submit = () => {
    setError(null)
    setFindings(null)
    setTimedOut(false)
    setSubmitting(true)

    const pending =
      mode === 'file' && file !== null
        ? uploadMessage(file, enrich)
        : submitUrl(url.trim(), enrich)

    pending
      .then((created) => {
        setMessage(created)
        setFile(null)
        setUrl('')
        if (fileInput.current) fileInput.current.value = ''
      })
      .catch((err: unknown) => {
        if (err instanceof IntakeError) setError(err.message)
        else setError(err instanceof Error ? err.message : 'Submission failed')
      })
      .finally(() => setSubmitting(false))
  }

  const canSubmit =
    !submitting && (mode === 'file' ? file !== null : url.trim().length > 0)

  const primary = findings?.find((finding) => finding.finding_type !== 'prompt_injection_attempt')
  const injection = findings?.find(
    (finding) => finding.finding_type === 'prompt_injection_attempt',
  )

  return (
    <>
      <div className="page-title">
        <h1>Phishing Detection</h1>
        <p className="subtitle">
          Submit a suspect email or link. Deterministic rules decide what is wrong; the
          model explains it and ranks what matters.
        </p>
      </div>

      <section className="panel">
        <h2>Submit a message</h2>

        <div className="tab-row">
          <button
            type="button"
            className={mode === 'file' ? 'btn btn-primary' : 'btn btn-ghost'}
            onClick={() => setMode('file')}
          >
            Email file
          </button>
          <button
            type="button"
            className={mode === 'url' ? 'btn btn-primary' : 'btn btn-ghost'}
            onClick={() => setMode('url')}
          >
            URL or domain
          </button>
        </div>

        {mode === 'file' ? (
          <div className="field">
            <label htmlFor="eml">Email file (.eml)</label>
            <input
              id="eml"
              ref={fileInput}
              type="file"
              accept=".eml,message/rfc822,text/plain"
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            />
            <p className="muted">
              Exported message, up to 2 MB. Attachment metadata is analysed; the
              attachment contents are hashed and discarded, never stored.
            </p>
          </div>
        ) : (
          <div className="field">
            <label htmlFor="url">URL</label>
            <input
              id="url"
              type="url"
              placeholder="https://example.test/login"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
            />
            <p className="muted">
              Loopback, private and reserved addresses are refused - they cannot be a
              phishing host.
            </p>
          </div>
        )}

        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={enrich}
            onChange={(event) => setEnrich(event.target.checked)}
          />
          <span>
            Inspect the link targets
            <em>
              This fetches the linked pages to follow redirects and look for a credential
              form. It is the only step that contacts the suspect host, which tells whoever
              runs it that the message is being investigated.
            </em>
          </span>
        </label>

        <button type="button" className="btn btn-primary" disabled={!canSubmit} onClick={submit}>
          {submitting ? 'Submitting…' : 'Analyse'}
        </button>

        {error !== null ? (
          <div className="error">
            <p>{error}</p>
          </div>
        ) : null}
      </section>

      {message !== null ? (
        <section className="panel">
          <h2>
            Analysis
            <VerdictBadge verdict={message.verdict} status={message.status} />
          </h2>

          <dl className="intake-summary">
            <div>
              <dt>Submitted</dt>
              {/* Untrusted: a filename or a URL the operator provided. Text only. */}
              <dd>{message.submitted_url ?? message.filename}</dd>
            </div>
            {message.sender !== null ? (
              <div>
                <dt>From</dt>
                <dd>{message.sender}</dd>
              </div>
            ) : null}
            {message.subject !== null ? (
              <div>
                <dt>Subject</dt>
                <dd>{message.subject}</dd>
              </div>
            ) : null}
          </dl>

          <IntakeProgress message={message} />

          {timedOut ? (
            <div className="error">
              <p>
                This is still running after two minutes and the page has stopped polling.
                Check the worker logs, then reload to pick the status back up.
              </p>
            </div>
          ) : null}

          {injection !== undefined ? (
            <div className="error">
              <strong>This message tried to instruct the analyser.</strong>
              <p>{injection.description}</p>
              <p className="muted">
                It was treated as data and never followed. The assessment below completed
                normally.
              </p>
            </div>
          ) : null}

          {primary !== undefined ? (
            <div className="verdict-detail">
              <div className="verdict-head">
                <SeverityBadge severity={primary.severity as Severity} />
                <h3>{primary.title}</h3>
              </div>
              <p>{primary.description}</p>
              {primary.recommendation !== null ? (
                <p className="recommendation">
                  <strong>Recommended action.</strong> {primary.recommendation}
                </p>
              ) : null}
              <p className="muted">
                Verdict {verdictOf(primary) || 'unknown'} · confidence{' '}
                {(primary.confidence * 100).toFixed(0)}%
              </p>

              <h3>Why</h3>
              <IndicatorList indicators={indicatorsOf(primary)} />
            </div>
          ) : null}
        </section>
      ) : null}

      <section className="panel">
        <h2>Recent submissions</h2>
        {history.length === 0 ? (
          <p className="muted">Nothing submitted yet.</p>
        ) : (
          <ul className="intake-history">
            {history.map((entry) => (
              <li key={entry.id}>
                <button type="button" className="intake-history-row" onClick={() => setMessage(entry)}>
                  <VerdictBadge verdict={entry.verdict} status={entry.status} />
                  <span className="intake-history-name">
                    {entry.submitted_url ?? entry.filename}
                  </span>
                  <span className="muted">
                    {entry.finding_count} finding(s) ·{' '}
                    {new Date(entry.created_at).toLocaleString()}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  )
}
