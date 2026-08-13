'use client'

import Link from 'next/link'
import { useState } from 'react'

import { IntakeProgress } from '@/components/intake/IntakeProgress'
import { IndicatorList } from '@/components/phishing/IndicatorList'
import { VerdictBadge } from '@/components/phishing/VerdictBadge'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader, Well } from '@/components/ui/Card'
import { Checkbox, Field, Input } from '@/components/ui/Field'
import { FileDropzone } from '@/components/ui/FileDropzone'
import {
  ArrowRight,
  Crosshair,
  Inbox,
  Link2,
  Mail,
  Send,
} from '@/components/ui/icons'
import { KeyValueList } from '@/components/ui/KeyValueList'
import { PageHeader, SectionHeader } from '@/components/ui/PageHeader'
import { EmptyState, InlineError } from '@/components/ui/states'
import {
  intakeIsFinished,
  useIntakeFindings,
  useMessage,
  useMessages,
  useSubmitUrl,
  useUploadMessage,
} from '@/lib/queries'
import { cn } from '@/lib/utils'
import type { Finding, Indicator, Message } from '@/types'

/**
 * The page that closes the loop: submit a message, watch it analyse, read the verdict.
 *
 * Restyled rather than rewritten — the flow works end to end and the invariants it presents are
 * the point of the whole agent:
 *
 * **Rules decide, the model explains.** The indicator list is deterministic Python output. The
 * write-up above it is the model's, and it is allowed to *raise* severity above the rules' floor
 * but never lower it.
 *
 * **An injection attempt is reported, not obeyed.** When a message contains text addressed to
 * the analyser, that becomes its own finding and the primary assessment still completes.
 *
 * **Everything from a message or a finding is rendered as text.** The subject, the sender, the
 * indicator facts and the model's explanation all derive from attacker-authored input, so
 * `dangerouslySetInnerHTML` must not appear anywhere in this file.
 *
 * Polling and the terminal-status stop now come from `useMessage`, replacing the hand-rolled
 * interval, attempt counter and cancelled flag this page used to carry.
 */

type Mode = 'file' | 'url'

function indicatorsOf(finding: Finding): Indicator[] {
  const raw = finding.evidence?.indicators
  return Array.isArray(raw) ? (raw as Indicator[]) : []
}

function verdictOf(finding: Finding): string {
  const raw = finding.evidence?.verdict
  return typeof raw === 'string' ? raw : ''
}

export default function PhishingPage() {
  const [mode, setMode] = useState<Mode>('file')
  const [file, setFile] = useState<File | null>(null)
  const [url, setUrl] = useState('')
  const [enrich, setEnrich] = useState(false)
  const [messageId, setMessageId] = useState<string | null>(null)

  const upload = useUploadMessage()
  const submit = useSubmitUrl()
  const message = useMessage(messageId ?? undefined)
  const finished = intakeIsFinished(message.data?.status)
  const findings = useIntakeFindings(messageId ? { messageId } : null, finished)
  const history = useMessages({ limit: 10 })

  const submissionError = upload.error ?? submit.error
  const busy = upload.isPending || submit.isPending
  const canSubmit = !busy && (mode === 'file' ? file !== null : url.trim().length > 0)

  const items = findings.data?.items ?? []
  const primary = items.find((finding) => finding.finding_type !== 'prompt_injection_attempt')
  const injection = items.find(
    (finding) => finding.finding_type === 'prompt_injection_attempt',
  )

  function start() {
    const onSuccess = (created: Message) => {
      setMessageId(created.id)
      setFile(null)
      setUrl('')
    }
    if (mode === 'file' && file) upload.mutate({ file, enrich }, { onSuccess })
    else if (mode === 'url') submit.mutate({ url: url.trim(), enrich }, { onSuccess })
  }

  return (
    <>
      <PageHeader
        title="Phishing analysis"
        description="Submit a suspect email or link. Deterministic rules decide what is wrong; the model explains it and ranks what matters — and it can raise a severity, never lower one."
      />

      <div className="grid gap-4 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)] lg:items-start">
        {/* Sticky from `lg` up. An assessment runs long — twenty indicators is normal — and
            without this the submit card scrolls away, leaving a tall empty column beside the
            reading and a trip back to the top to queue the next message. */}
        <Card className="lg:sticky lg:top-6">
          <CardHeader title="Submit" />
          <CardBody className="space-y-4">
            <div
              role="group"
              aria-label="Submission type"
              className="grid grid-cols-2 gap-1 rounded-md border border-border-default p-1"
            >
              {(
                [
                  { value: 'file', label: 'Email file', Icon: Mail },
                  { value: 'url', label: 'URL', Icon: Link2 },
                ] as const
              ).map(({ value, label, Icon }) => (
                <button
                  key={value}
                  type="button"
                  aria-pressed={mode === value}
                  onClick={() => setMode(value)}
                  className={cn(
                    'flex items-center justify-center gap-1.5 rounded-sm px-2 py-1.5',
                    'text-body-sm font-medium transition-colors duration-(--duration-fast)',
                    mode === value
                      ? 'bg-accent-surface text-accent'
                      : 'text-text-tertiary hover:bg-surface-raised-hover hover:text-text-secondary',
                  )}
                >
                  <Icon className="size-3.5" aria-hidden />
                  {label}
                </button>
              ))}
            </div>

            {mode === 'file' ? (
              <FileDropzone
                label="Email file"
                accept=".eml,message/rfc822,text/plain"
                hint="Exported .eml, up to 2 MB. Attachment metadata is analysed; attachment contents are hashed and discarded, never stored."
                selected={file}
                onSelect={setFile}
                onClear={() => setFile(null)}
                disabled={busy}
              />
            ) : (
              <Field
                label="URL or domain"
                hint="Loopback, private and reserved addresses are refused — they cannot be a phishing host."
              >
                <Input
                  type="url"
                  placeholder="https://example.test/login"
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  disabled={busy}
                />
              </Field>
            )}

            <Checkbox
              checked={enrich}
              onChange={(event) => setEnrich(event.target.checked)}
              disabled={busy}
              label="Inspect the link targets"
              description="Fetches the linked pages to follow redirects and look for a credential form. This is the only step that contacts the suspect host, which tells whoever runs it that the message is being investigated."
            />

            {submissionError ? <InlineError error={submissionError} /> : null}

            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="primary"
                leadingIcon={<Send className="size-4" />}
                disabled={!canSubmit}
                loading={busy}
                onClick={start}
              >
                Analyse
              </Button>
              {messageId ? (
                <Button variant="ghost" onClick={() => setMessageId(null)}>
                  Clear
                </Button>
              ) : null}
            </div>
          </CardBody>
        </Card>

        <div className="space-y-4">
          {message.data ? (
            <Card>
              <CardHeader
                title="Analysis"
                actions={
                  <VerdictBadge
                    verdict={message.data.verdict}
                    status={message.data.status}
                  />
                }
              />
              <CardBody className="space-y-5">
                <KeyValueList
                  items={[
                    {
                      label: 'Submitted',
                      // Untrusted: a filename or a URL the operator provided.
                      value: message.data.submitted_url ?? message.data.filename,
                      mono: true,
                    },
                    {
                      label: 'From',
                      value: message.data.sender ?? '',
                      when: Boolean(message.data.sender),
                      mono: true,
                    },
                    {
                      label: 'Subject',
                      value: message.data.subject ?? '',
                      when: Boolean(message.data.subject),
                    },
                  ]}
                />

                <IntakeProgress
                  status={message.data.status}
                  error={message.data.error}
                  summary={[
                    { label: 'findings', value: message.data.finding_count },
                    { label: 'links', value: message.data.link_count },
                    { label: 'attachments', value: message.data.attachment_count },
                  ]}
                />

                {injection ? (
                  <div
                    role="alert"
                    className="rounded-md border border-severity-critical/30 bg-severity-critical-bg px-3.5 py-3"
                  >
                    <p className="flex items-center gap-2 text-body-sm font-semibold text-text-primary">
                      <Crosshair
                        className="size-4 shrink-0 text-severity-critical"
                        aria-hidden
                      />
                      This message tried to instruct the analyser
                    </p>
                    <p className="mt-1.5 text-body-sm text-text-secondary">
                      {injection.description}
                    </p>
                    <p className="mt-1.5 text-caption text-text-tertiary">
                      It was fenced as data and never followed. The assessment below completed
                      normally.
                    </p>
                  </div>
                ) : null}

                {findings.error ? (
                  <InlineError
                    error={findings.error}
                    onRetry={() => void findings.refetch()}
                  />
                ) : null}

                {primary ? (
                  <div className="space-y-4 border-t border-border-subtle pt-4">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={primary.severity} />
                        <Badge tone="neutral" size="sm">
                          {verdictOf(primary) || 'verdict unknown'}
                        </Badge>
                        <span className="text-caption text-text-tertiary">
                          confidence{' '}
                          <span data-numeric>
                            {Math.round(primary.confidence * 100)}%
                          </span>
                        </span>
                      </div>
                      <h3 className="mt-2 text-heading font-semibold text-text-primary">
                        {primary.title}
                      </h3>
                      <p className="mt-1.5 text-body leading-relaxed text-text-secondary">
                        {primary.description}
                      </p>
                    </div>

                    {primary.recommendation ? (
                      <p className="rounded-md border-l-2 border-accent bg-accent-surface px-3.5 py-2.5 text-body text-text-secondary">
                        <span className="font-medium text-text-primary">
                          Recommended action.
                        </span>{' '}
                        {primary.recommendation}
                      </p>
                    ) : null}

                    <div>
                      <SectionHeader
                        className="mb-2"
                        title="Why"
                        description="Every indicator below was found by deterministic Python, before any model saw the message."
                      />
                      <IndicatorList indicators={indicatorsOf(primary)} />
                    </div>

                    <Button
                      variant="secondary"
                      size="sm"
                      href={`/findings/${primary.id}`}
                      trailingIcon={<ArrowRight className="size-3.5" />}
                    >
                      Open as a finding
                    </Button>
                  </div>
                ) : findings.isPending || findings.isFetching ? (
                  /* `isPending` alone is not enough. Between the intake reaching `completed`
                     and the findings request settling, the query is neither pending nor
                     populated, and this branch briefly rendered "recorded no finding" on a
                     message that had two. A momentary false clean is the one failure this
                     agent must never produce, so the wait is stated instead. */
                  <p className="text-body-sm text-text-tertiary">Loading the assessment…</p>
                ) : finished && message.data.status === 'completed' ? (
                  <Well className="py-3">
                    <p className="text-body-sm text-text-secondary">
                      Analysis completed and recorded no finding. Nothing the rules check
                      fired.
                    </p>
                  </Well>
                ) : null}
              </CardBody>
            </Card>
          ) : (
            <Card>
              <CardBody>
                <EmptyState
                  icon={<Mail className="size-5" />}
                  title="Nothing submitted yet"
                  description="Drop an exported message or paste a link. The verdict, the model's explanation and every indicator behind it appear here."
                />
              </CardBody>
            </Card>
          )}
        </div>
      </div>

      <SectionHeader
        className="mt-8"
        title="Recent submissions"
        description="Select one to reopen its analysis."
      />
      <Card>
        {history.isPending ? (
          <CardBody>
            <p className="text-body-sm text-text-tertiary">Loading submissions…</p>
          </CardBody>
        ) : history.error ? (
          <CardBody>
            <InlineError error={history.error} onRetry={() => void history.refetch()} />
          </CardBody>
        ) : (history.data?.items.length ?? 0) === 0 ? (
          <EmptyState
            icon={<Inbox className="size-5" />}
            title="No submissions"
            description="Every message analysed is listed here, newest first."
          />
        ) : (
          <ul className="divide-y divide-border-subtle">
            {history.data?.items.map((entry) => (
              <li key={entry.id}>
                <button
                  type="button"
                  onClick={() => setMessageId(entry.id)}
                  aria-current={entry.id === messageId ? 'true' : undefined}
                  className={cn(
                    'flex w-full flex-wrap items-center gap-x-3 gap-y-1.5 px-4 py-3 text-left',
                    'transition-colors duration-(--duration-fast) hover:bg-surface-raised-hover',
                    entry.id === messageId && 'bg-surface-raised-hover',
                  )}
                >
                  <VerdictBadge verdict={entry.verdict} status={entry.status} size="sm" />
                  <span className="min-w-0 flex-1">
                    {/* Untrusted: a filename or URL the submitter chose. */}
                    <span className="block truncate font-mono text-body-sm text-text-primary">
                      {entry.submitted_url ?? entry.filename}
                    </span>
                    {entry.subject ? (
                      <span className="mt-0.5 block truncate text-caption text-text-tertiary">
                        {entry.subject}
                      </span>
                    ) : null}
                  </span>
                  <span className="shrink-0 text-caption text-text-tertiary">
                    <span data-numeric>{entry.finding_count}</span> finding
                    {entry.finding_count === 1 ? '' : 's'} ·{' '}
                    {new Date(entry.created_at).toLocaleString()}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <p className="mt-4 text-caption text-text-tertiary">
        Analysing a message stores its raw bytes, capped at 2 MB, so a verdict can be
        re-derived. Attachment contents are hashed and discarded. See{' '}
        <Link href="/findings?agent=phishing" className="text-accent hover:underline">
          all phishing findings
        </Link>
        .
      </p>
    </>
  )
}
