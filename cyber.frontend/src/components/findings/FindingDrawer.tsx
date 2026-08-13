'use client'

import Link from 'next/link'

import { Badge } from '@/components/ui/Badge'
import { SeverityBadge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Well } from '@/components/ui/Card'
import { ArrowRight, Clock, Server, Shield } from '@/components/ui/icons'
import { Drawer } from '@/components/ui/overlays'
import { Eyebrow } from '@/components/ui/PageHeader'
import {
  FINDING_TYPE_LABEL,
  STATUS_LABEL,
  formatLocation,
  isRulesOnly,
  latestVerification,
  readPriority,
  VERIFICATION_CLASS,
  VERIFICATION_LABEL,
} from '@/lib/findings'
import { cn } from '@/lib/utils'
import type { Finding } from '@/types'

/**
 * Triage panel for one finding, opened from the table.
 *
 * A drawer rather than a navigation, because triaging a queue means opening twenty findings
 * in a row and the list's filters and scroll position should survive all twenty. The full
 * page at `/findings/[id]` still exists for a deep link or a shared URL.
 *
 * Everything drawn from `evidence` is rendered as text. It holds scanner banners and
 * attacker-authored message content, so React's escaping is the guard — no
 * `dangerouslySetInnerHTML` anywhere near this component.
 */
export function FindingDrawer({
  finding,
  open,
  onClose,
}: {
  finding: Finding | null
  open: boolean
  onClose: () => void
}) {
  if (!finding) return null

  const priority = readPriority(finding)
  const verification = latestVerification(finding)
  const location = formatLocation(finding)

  return (
    <Drawer
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose()
      }}
      title={finding.title}
      header={
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <Badge tone="neutral">{FINDING_TYPE_LABEL[finding.finding_type]}</Badge>
          <Badge tone="neutral">{STATUS_LABEL[finding.status]}</Badge>
          {isRulesOnly(finding) ? (
            <Badge tone="warn">Rules only — not explained by a model</Badge>
          ) : null}
        </div>
      }
      footer={
        <Button href={`/findings/${finding.id}`} variant="primary" trailingIcon={<ArrowRight className="size-4" />}>
          Open full detail
        </Button>
      }
    >
      <div className="space-y-5">
        <section>
          <Eyebrow>What was found</Eyebrow>
          <p className="mt-1.5 text-body leading-relaxed text-text-secondary">
            {finding.description}
          </p>
        </section>

        {finding.recommendation ? (
          <section>
            <Eyebrow>Recommended action</Eyebrow>
            <p className="mt-1.5 rounded-md border-l-2 border-accent bg-accent-surface px-3 py-2 text-body text-text-secondary">
              {finding.recommendation}
            </p>
          </section>
        ) : null}

        <section className="grid gap-3 sm:grid-cols-2">
          <Detail icon={<Server className="size-3.5" />} label="Location" value={location || '—'} />
          <Detail
            icon={<Shield className="size-3.5" />}
            label="Confidence"
            value={`${Math.round(finding.confidence * 100)}%`}
          />
          <Detail
            icon={<Clock className="size-3.5" />}
            label="Detected"
            value={new Date(finding.detected_at).toLocaleString()}
          />
          <Detail label="Source" value={finding.source} />
        </section>

        {finding.cve_ids.length > 0 ? (
          <section>
            <Eyebrow>Correlated CVEs</Eyebrow>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {finding.cve_ids.map((cve) => (
                <Link
                  key={cve}
                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="rounded-full border border-border-default bg-surface-sunken px-2 py-0.5 font-mono text-caption text-text-secondary transition-colors hover:border-accent-border hover:text-accent"
                >
                  {cve}
                </Link>
              ))}
            </div>
          </section>
        ) : null}

        {priority ? (
          <section>
            <Eyebrow>Priority</Eyebrow>
            <p className="mt-1.5 text-body-sm text-text-secondary">
              Rank <span data-numeric>{priority.rank}</span> — scored{' '}
              <span data-numeric>{priority.score}</span> of{' '}
              <span data-numeric>{priority.max_score}</span>, computed by the rule engine
              rather than by a model.
            </p>
          </section>
        ) : null}

        {verification ? (
          <section>
            <Eyebrow>Last re-check</Eyebrow>
            <p className={cn('mt-1.5 text-body-sm font-medium', VERIFICATION_CLASS[verification.outcome])}>
              {VERIFICATION_LABEL[verification.outcome]}
            </p>
            {verification.reason ? (
              <p className="mt-1 text-body-sm text-text-secondary">{verification.reason}</p>
            ) : null}
          </section>
        ) : null}

        {finding.asset ? (
          <section>
            <Eyebrow>Evidence</Eyebrow>
            {/* Untrusted. Rendered as text inside a well, which signals "captured
                material" rather than "our words". */}
            <Well className="mt-1.5 max-h-52 overflow-y-auto">
              <pre className="whitespace-pre-wrap break-words font-mono text-caption leading-4 text-text-tertiary">
                {JSON.stringify(finding.evidence, null, 2)}
              </pre>
            </Well>
          </section>
        ) : null}
      </div>
    </Drawer>
  )
}

function Detail({
  icon,
  label,
  value,
}: {
  icon?: React.ReactNode
  label: string
  value: string
}) {
  return (
    <div>
      <Eyebrow>
        <span className="inline-flex items-center gap-1.5">
          {icon ? <span aria-hidden>{icon}</span> : null}
          {label}
        </span>
      </Eyebrow>
      <p className="mt-1 break-words text-body-sm text-text-primary">{value}</p>
    </div>
  )
}
