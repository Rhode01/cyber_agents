'use client'

import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useState } from 'react'

import { PriorityBreakdown } from '@/components/findings/PriorityBreakdown'
import { VerificationHistory } from '@/components/findings/VerificationHistory'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader, Well } from '@/components/ui/Card'
import {
  AGENT_ICON,
  Clock,
  ExternalLink,
  Gauge,
  RefreshCw,
  Server,
  Trash2,
} from '@/components/ui/icons'
import { KeyValueList } from '@/components/ui/KeyValueList'
import { Modal, TabPanel } from '@/components/ui/overlays'
import { Eyebrow, PageHeader } from '@/components/ui/PageHeader'
import { ErrorState, InlineError, LoadingState } from '@/components/ui/states'
import {
  FINDING_TYPE_HINT,
  FINDING_TYPE_LABEL,
  STATUS_LABEL,
  formatLocation,
  isRulesOnly,
  readPriority,
  readVerification,
} from '@/lib/findings'
import { useDeleteFinding, useFinding, useVerifyFindings } from '@/lib/queries'
import type { Finding } from '@/types'

/**
 * One finding, in full.
 *
 * The drawer on `/findings` covers triage; this page is the deep link — the URL you paste
 * into a ticket. It therefore shows everything, including the parts the drawer omits:
 * priority arithmetic, the whole verification history, provenance, and the raw evidence blob.
 *
 * Grouped into tabs rather than one long scroll. Six sections of unequal relevance stacked
 * vertically means the interesting one is always somewhere below the fold, and the tab labels
 * double as a statement of what the platform knows about a finding.
 *
 * **Everything from `evidence` is rendered as text.** It carries scanner banners and
 * attacker-authored message content. `dangerouslySetInnerHTML` must not appear in this file.
 */

/** Evidence is untrusted banner content. Read defensively and render as text. */
function evidenceString(finding: Finding, key: string): string | null {
  const value = finding.evidence?.[key]
  return typeof value === 'string' && value.trim() ? value : null
}

/**
 * How the finding was established, in one sentence.
 *
 * Worth stating plainly rather than leaving implicit: a rules-only finding means no model was
 * involved at all, which is a stronger claim than a model-written one, not a weaker one.
 */
function provenance(finding: Finding): string {
  if (finding.agent === 'phishing') {
    return isRulesOnly(finding)
      ? 'Established by the deterministic rule engine. No model was involved in this finding.'
      : 'Indicators were found by the deterministic rule engine, then explained by a model. The model can raise the severity above the rules’ floor but never lower it, and it cannot invent an indicator.'
  }
  if (finding.agent !== 'vulnerability') {
    return `Produced by the ${finding.agent} agent.`
  }
  return isRulesOnly(finding)
    ? 'Established by the deterministic rule engine. No model was involved in this finding.'
    : 'Established by the deterministic rule engine, then written up by a model. The model cannot create a finding or a CVE id.'
}

export default function FindingDetailPage() {
  const params = useParams()
  const router = useRouter()
  const id = params.id as string

  const query = useFinding(id)
  const remove = useDeleteFinding()
  const verify = useVerifyFindings()

  const [confirmDelete, setConfirmDelete] = useState(false)

  const finding = query.data

  if (query.isPending) {
    return (
      <>
        <PageHeader
          title="Finding"
          breadcrumbs={[{ label: 'Findings', href: '/findings' }, { label: 'Loading…' }]}
        />
        <Card>
          <LoadingState message="Loading finding" />
        </Card>
      </>
    )
  }

  if (query.error || !finding) {
    return (
      <>
        <PageHeader
          title="Finding"
          breadcrumbs={[{ label: 'Findings', href: '/findings' }, { label: 'Not available' }]}
        />
        <Card>
          <ErrorState
            error={query.error}
            onRetry={() => void query.refetch()}
            title="This finding could not be loaded"
          />
        </Card>
      </>
    )
  }

  const priority = readPriority(finding)
  const verification = readVerification(finding)
  const fact = evidenceString(finding, 'fact')
  const rationale = evidenceString(finding, 'rationale')
  const ruleId = evidenceString(finding, 'rule_id')
  const AgentIcon = AGENT_ICON[finding.agent]

  return (
    <>
      <PageHeader
        breadcrumbs={[
          { label: 'Findings', href: '/findings' },
          { label: FINDING_TYPE_LABEL[finding.finding_type] },
        ]}
        title={finding.title}
        meta={
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <Badge tone="neutral">{STATUS_LABEL[finding.status]}</Badge>
            {isRulesOnly(finding) ? <Badge tone="warn">Rules only</Badge> : null}
          </div>
        }
        description={FINDING_TYPE_HINT[finding.finding_type]}
        actions={
          <>
            <Button
              variant="secondary"
              leadingIcon={<RefreshCw className="size-4" />}
              loading={verify.isPending}
              onClick={() => verify.mutate({ finding_ids: [id] })}
            >
              Re-check
            </Button>
            <Button
              variant="danger"
              leadingIcon={<Trash2 className="size-4" />}
              onClick={() => setConfirmDelete(true)}
            >
              Delete
            </Button>
          </>
        }
      />

      {verify.isSuccess ? (
        <Well className="mb-4 px-4 py-2.5 text-body-sm text-text-secondary">
          {verify.data.detail}{' '}
          {verify.data.queued > 0
            ? 'The re-check runs a scan out of band — reload once it finishes to see the outcome below.'
            : null}
        </Well>
      ) : null}
      {verify.error ? (
        <InlineError error={verify.error} className="mb-4" />
      ) : null}
      {remove.error ? <InlineError error={remove.error} className="mb-4" /> : null}

      <TabPanel
        tabs={[
          {
            value: 'overview',
            label: 'Overview',
            content: (
              <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)] lg:items-start">
                <div className="space-y-4">
                  <Card>
                    <CardBody className="space-y-5">
                      <section>
                        <Eyebrow>What was found</Eyebrow>
                        <p className="mt-1.5 whitespace-pre-wrap text-body leading-relaxed text-text-secondary">
                          {finding.description}
                        </p>
                      </section>

                      {rationale ? (
                        <section>
                          <Eyebrow>Why it matters</Eyebrow>
                          <p className="mt-1.5 whitespace-pre-wrap text-body text-text-secondary">
                            {rationale}
                          </p>
                        </section>
                      ) : null}

                      {finding.recommendation ? (
                        <section>
                          <Eyebrow>Recommended action</Eyebrow>
                          <p className="mt-1.5 whitespace-pre-wrap rounded-md border-l-2 border-accent bg-accent-surface px-3.5 py-2.5 text-body text-text-secondary">
                            {finding.recommendation}
                          </p>
                        </section>
                      ) : null}
                    </CardBody>
                  </Card>

                  {finding.cve_ids.length > 0 ? (
                    <Card>
                      <CardHeader
                        title="Correlated CVEs"
                        description="Produced by the rule engine from the observed version, never by a model."
                      />
                      <CardBody>
                        <div className="flex flex-wrap gap-1.5">
                          {finding.cve_ids.map((cve) => (
                            <Link
                              key={cve}
                              href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                              target="_blank"
                              rel="noreferrer noopener"
                              className="inline-flex items-center gap-1 rounded-full border border-border-default bg-surface-sunken px-2.5 py-1 font-mono text-caption text-text-secondary transition-colors hover:border-accent-border hover:text-accent"
                            >
                              {cve}
                              <ExternalLink className="size-3 opacity-60" aria-hidden />
                            </Link>
                          ))}
                        </div>
                      </CardBody>
                    </Card>
                  ) : null}
                </div>

                <Card>
                  <CardHeader title="Details" />
                  <CardBody className="space-y-5">
                    <KeyValueList
                      columns={1}
                      items={[
                        {
                          label: 'Location',
                          value: formatLocation(finding),
                          icon: <Server className="size-3.5" />,
                          mono: true,
                        },
                        {
                          label: 'Service',
                          value: finding.service ?? '',
                          when: Boolean(finding.service),
                          mono: true,
                        },
                        {
                          label: 'Agent',
                          value: (
                            <span className="inline-flex items-center gap-1.5 capitalize">
                              <AgentIcon className="size-3.5 text-text-tertiary" aria-hidden />
                              {finding.agent}
                            </span>
                          ),
                        },
                        {
                          label: 'Confidence',
                          value: `${Math.round(finding.confidence * 100)}%`,
                          icon: <Gauge className="size-3.5" />,
                        },
                        {
                          label: 'Detected',
                          value: new Date(finding.detected_at).toLocaleString(),
                          icon: <Clock className="size-3.5" />,
                        },
                        { label: 'Source', value: finding.source, mono: true },
                        {
                          label: 'Raw reference',
                          value: finding.raw_reference ?? '',
                          when: Boolean(finding.raw_reference),
                          mono: true,
                        },
                      ]}
                    />

                    <div className="border-t border-border-subtle pt-4">
                      <Eyebrow>Provenance</Eyebrow>
                      <p className="mt-1.5 text-body-sm text-text-secondary">
                        {provenance(finding)}
                        {ruleId ? (
                          <>
                            {' '}
                            Rule{' '}
                            <code className="font-mono text-caption text-text-primary">
                              {ruleId}
                            </code>
                            .
                          </>
                        ) : null}
                      </p>
                    </div>

                    {finding.scan_id || finding.message_id || finding.run_id ? (
                      <div className="border-t border-border-subtle pt-4">
                        <Eyebrow>Came from</Eyebrow>
                        <div className="mt-1.5 flex flex-wrap gap-2">
                          {finding.scan_id ? (
                            <Button size="sm" variant="secondary" href="/scans">
                              Scan intake
                            </Button>
                          ) : null}
                          {finding.message_id ? (
                            <Button size="sm" variant="secondary" href="/phishing">
                              Message intake
                            </Button>
                          ) : null}
                          {finding.run_id ? (
                            <Button size="sm" variant="secondary" href="/run">
                              Pipeline run
                            </Button>
                          ) : null}
                        </div>
                      </div>
                    ) : null}
                  </CardBody>
                </Card>
              </div>
            ),
          },
          {
            value: 'observed',
            label: 'Observed',
            content: (
              <Card>
                <CardHeader
                  title="What the rule engine actually saw"
                  description="Captured from the assessed artifact. Untrusted text, rendered verbatim."
                />
                <CardBody className="space-y-4">
                  {fact ? (
                    <Well>
                      <p className="whitespace-pre-wrap break-words font-mono text-caption leading-5 text-text-secondary">
                        {fact}
                      </p>
                    </Well>
                  ) : (
                    <p className="text-body-sm text-text-tertiary">
                      This finding carries no single observed fact. The full evidence blob is
                      under Raw.
                    </p>
                  )}
                </CardBody>
              </Card>
            ),
          },
          {
            value: 'priority',
            label: 'Priority',
            content: priority ? (
              <PriorityBreakdown priority={priority} />
            ) : (
              <Card>
                <CardBody>
                  <p className="text-body-sm text-text-tertiary">
                    No remediation score. Only the vulnerability agent’s rule engine computes
                    one, so its absence here is normal rather than a gap.
                  </p>
                </CardBody>
              </Card>
            ),
          },
          {
            value: 'verification',
            label: 'Verification',
            count: verification.length,
            content: (
              <Card>
                <CardHeader
                  title="Re-check history"
                  description="Only a scan that provably covered this host and port can close a finding."
                />
                <CardBody>
                  <VerificationHistory entries={verification} />
                </CardBody>
              </Card>
            ),
          },
          {
            value: 'raw',
            label: 'Raw',
            content: (
              <Card>
                <CardHeader
                  title="Evidence"
                  description="Everything above is drawn from this. Shown for the parts the page does not model yet."
                />
                <CardBody>
                  <Well className="max-h-[32rem] overflow-auto">
                    <pre className="whitespace-pre-wrap break-words font-mono text-caption leading-5 text-text-tertiary">
                      {JSON.stringify(finding.evidence, null, 2)}
                    </pre>
                  </Well>
                </CardBody>
              </Card>
            ),
          },
        ]}
      />

      <Modal
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title="Delete this finding?"
        description="It is removed from the database permanently. Re-running the scan that produced it will create it again."
        size="sm"
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={remove.isPending}
              onClick={() =>
                remove.mutate(id, {
                  onSuccess: () => router.push('/findings'),
                  onError: () => setConfirmDelete(false),
                })
              }
            >
              Delete finding
            </Button>
          </>
        }
      >
        <p className="text-body-sm text-text-secondary">{finding.title}</p>
        <p className="mt-1 font-mono text-caption text-text-tertiary">
          {formatLocation(finding)}
        </p>
      </Modal>
    </>
  )
}
