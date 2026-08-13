'use client'

import Link from 'next/link'
import { useMemo } from 'react'

import { SeverityBadge, SeverityTally } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { DistributionBar, SeverityBarChart } from '@/components/ui/charts'
import { AGENT_ICON, FileText, Gauge, Layers, Printer, Server } from '@/components/ui/icons'
import { Eyebrow, PageHeader, SectionHeader } from '@/components/ui/PageHeader'
import { StatCard, StatGrid } from '@/components/ui/StatCard'
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/states'
import { readAssetRanking, readPriority } from '@/lib/findings'
import { useFindings } from '@/lib/queries'
import { SEVERITY_LABEL, SEVERITY_ORDER, emptySeverityCounts } from '@/lib/severity'
import type { Severity } from '@/types'

/**
 * The posture report — a page built to be printed.
 *
 * The old version headlined an invented "Risk Score /10": the mean severity weight across every
 * finding. It read low precisely when it should have read high, because three criticals among
 * two hundred lows average out to nothing. That number is gone.
 *
 * What replaces it is the score the ai.engine actually computes. `readAssetRanking` returns the
 * engine's per-asset ranking, scored deterministically on each asset's single worst finding, and
 * the headline is the worst of those. It is a real number with a real derivation, and when the
 * engine has not produced one this page says so rather than substituting a guess.
 *
 * Print is a first-class output, not an afterthought: `globals.css` flips the token palette to
 * light under `@media print`, and `data-print-hide` drops the controls.
 */

const REPORT_LIMIT = 200

export default function ReportsPage() {
  const query = useFindings({ limit: REPORT_LIMIT })
  const findings = useMemo(() => query.data?.items ?? [], [query.data])
  const total = query.data?.total ?? 0
  const capped = total > findings.length

  const metrics = useMemo(() => {
    const bySeverity = emptySeverityCounts()
    const byAgent = new Map<string, number>()
    const byAsset = new Map<string, Record<Severity, number>>()
    const bySource = new Map<string, number>()

    for (const finding of findings) {
      bySeverity[finding.severity] += 1
      byAgent.set(finding.agent, (byAgent.get(finding.agent) ?? 0) + 1)
      bySource.set(finding.source, (bySource.get(finding.source) ?? 0) + 1)
      if (finding.asset) {
        const counts = byAsset.get(finding.asset) ?? emptySeverityCounts()
        counts[finding.severity] += 1
        byAsset.set(finding.asset, counts)
      }
    }

    return { bySeverity, byAgent, byAsset, bySource }
  }, [findings])

  /** The engine's own ranking. Empty for agents with no rule engine, which is normal. */
  const ranking = useMemo(() => readAssetRanking(findings), [findings])

  /** Highest engine-computed remediation score across every finding that carries one. */
  const worstScore = useMemo(() => {
    let worst: number | null = null
    for (const finding of findings) {
      const priority = readPriority(finding)
      if (priority && (worst === null || priority.score > worst)) worst = priority.score
    }
    return worst
  }, [findings])

  const topAssets = useMemo(
    () =>
      [...metrics.byAsset.entries()]
        .map(([asset, counts]) => ({
          asset,
          counts,
          count: SEVERITY_ORDER.reduce((sum, severity) => sum + counts[severity], 0),
          worst: SEVERITY_ORDER.find((severity) => counts[severity] > 0) ?? 'info',
        }))
        // Worst severity first, then volume. Sorting on volume alone puts a host with
        // twenty informational findings above one with a single critical.
        .sort(
          (a, b) =>
            SEVERITY_ORDER.indexOf(a.worst as Severity) -
              SEVERITY_ORDER.indexOf(b.worst as Severity) || b.count - a.count,
        )
        .slice(0, 8),
    [metrics.byAsset],
  )

  if (query.isPending) {
    return (
      <>
        <PageHeader title="Posture report" />
        <Card>
          <LoadingState message="Aggregating findings" />
        </Card>
      </>
    )
  }

  if (query.error) {
    return (
      <>
        <PageHeader title="Posture report" />
        <Card>
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        </Card>
      </>
    )
  }

  return (
    <>
      <PageHeader
        title="Posture report"
        description={
          capped
            ? `Aggregated across the newest ${findings.length} of ${total} findings. Every number below is computed from those records.`
            : `Aggregated across all ${total} recorded findings. Every number below is computed from those records.`
        }
        actions={
          <span data-print-hide>
            <Button
              variant="secondary"
              leadingIcon={<Printer className="size-4" />}
              onClick={() => window.print()}
            >
              Print
            </Button>
          </span>
        }
      />

      {findings.length === 0 ? (
        <Card>
          <EmptyState
            icon={<FileText className="size-5" />}
            title="Nothing to report yet"
            description="A report needs findings. Upload a scanner report or submit a suspect message and this page fills in."
            action={
              <div className="flex flex-wrap justify-center gap-2">
                <Button href="/scans" variant="primary">
                  Upload a scan
                </Button>
                <Button href="/run" variant="secondary">
                  Run agents
                </Button>
              </div>
            }
          />
        </Card>
      ) : (
        <>
          <StatGrid>
            <StatCard
              label="Findings"
              value={findings.length}
              hint={capped ? `of ${total} recorded` : 'every record'}
              icon={<Layers className="size-4" />}
            />
            <StatCard
              label="Worst remediation score"
              value={worstScore === null ? '—' : Math.round(worstScore)}
              tone={worstScore === null ? 'default' : 'critical'}
              hint={
                worstScore === null
                  ? 'no finding carries an engine score'
                  : 'computed by the rule engine, out of 100'
              }
              icon={<Gauge className="size-4" />}
            />
            <StatCard
              label="Agents reporting"
              value={metrics.byAgent.size}
              hint="of 4 detection agents"
            />
            <StatCard
              label="Assets affected"
              value={metrics.byAsset.size}
              tone={metrics.byAsset.size > 0 ? 'high' : 'default'}
              hint="named in at least one finding"
              icon={<Server className="size-4" />}
            />
          </StatGrid>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader
                title="Severity distribution"
                description="Every finding in this report, by how bad it is."
              />
              <CardBody className="space-y-4">
                <DistributionBar counts={metrics.bySeverity} className="h-2" />
                <SeverityBarChart counts={metrics.bySeverity} height={180} />
                <dl className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3">
                  {SEVERITY_ORDER.map((severity) => (
                    <div key={severity} className="flex items-baseline justify-between gap-2">
                      <dt className="text-body-sm text-text-secondary">
                        {SEVERITY_LABEL[severity]}
                      </dt>
                      <dd
                        className="font-mono text-body-sm text-text-primary"
                        data-numeric
                      >
                        {metrics.bySeverity[severity]}
                      </dd>
                    </div>
                  ))}
                </dl>
              </CardBody>
            </Card>

            <Card>
              <CardHeader
                title="By agent"
                description="Which detector produced what."
              />
              <CardBody>
                <ul className="space-y-2.5">
                  {[...metrics.byAgent.entries()]
                    .sort((a, b) => b[1] - a[1])
                    .map(([agent, count]) => {
                      const Icon = AGENT_ICON[agent as keyof typeof AGENT_ICON]
                      const share = (count / findings.length) * 100
                      return (
                        <li key={agent} className="flex items-center gap-3">
                          <span className="flex w-32 shrink-0 items-center gap-2 text-body-sm capitalize text-text-secondary">
                            {Icon ? (
                              <Icon className="size-3.5 text-text-tertiary" aria-hidden />
                            ) : null}
                            {agent}
                          </span>
                          <span className="h-1.5 min-w-8 flex-1 overflow-hidden rounded-full bg-surface-sunken">
                            <span
                              className="block h-full rounded-full bg-accent"
                              style={{ width: `${share}%` }}
                            />
                          </span>
                          <span
                            className="w-12 shrink-0 text-right font-mono text-caption text-text-secondary"
                            data-numeric
                          >
                            {count}
                          </span>
                        </li>
                      )
                    })}
                </ul>

                <div className="mt-5 border-t border-border-subtle pt-4">
                  <Eyebrow>Source tools</Eyebrow>
                  <ul className="mt-1.5 space-y-1">
                    {[...metrics.bySource.entries()]
                      .sort((a, b) => b[1] - a[1])
                      .map(([source, count]) => (
                        <li
                          key={source}
                          className="flex items-baseline justify-between gap-3 text-body-sm"
                        >
                          <span className="min-w-0 truncate font-mono text-caption text-text-secondary">
                            {source}
                          </span>
                          <span
                            className="shrink-0 font-mono text-caption text-text-primary"
                            data-numeric
                          >
                            {count}
                          </span>
                        </li>
                      ))}
                  </ul>
                </div>
              </CardBody>
            </Card>
          </div>

          {ranking.length > 0 ? (
            <>
              <SectionHeader
                className="mt-8"
                title="Remediation order"
                description="The ai.engine's own ranking, scored on each asset's single worst finding. Deterministic — not model output."
              />
              <Card>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[36rem] text-body-sm">
                    <caption className="sr-only">
                      Assets ranked by engine-computed remediation score
                    </caption>
                    <thead>
                      <tr className="border-b border-border-subtle text-caption uppercase tracking-wide text-text-tertiary">
                        <th scope="col" className="px-4 py-2 text-left font-medium">
                          Asset
                        </th>
                        <th scope="col" className="px-4 py-2 text-left font-medium">
                          Worst
                        </th>
                        <th scope="col" className="px-4 py-2 text-left font-medium">
                          Breakdown
                        </th>
                        <th scope="col" className="px-4 py-2 text-right font-medium">
                          Score
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-subtle">
                      {ranking.map((risk) => (
                        <tr key={risk.asset}>
                          <td className="px-4 py-2.5">
                            <Link
                              href={`/findings?q=${encodeURIComponent(risk.asset)}`}
                              className="font-mono text-caption text-text-primary transition-colors hover:text-accent"
                            >
                              {risk.asset}
                            </Link>
                          </td>
                          <td className="px-4 py-2.5">
                            <SeverityBadge severity={risk.worst_severity} size="sm" />
                          </td>
                          <td className="px-4 py-2.5">
                            <SeverityTally
                              counts={fillCounts(risk.severities)}
                              order={SEVERITY_ORDER}
                            />
                          </td>
                          <td className="px-4 py-2.5 text-right">
                            <span className="font-mono text-caption text-accent" data-numeric>
                              {Math.round(risk.top_score)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </>
          ) : null}

          <SectionHeader
            className="mt-8"
            title="Most affected assets"
            description="Ordered by worst severity first, then by volume — twenty informational findings do not outrank one critical."
          />
          <Card>
            {topAssets.length === 0 ? (
              <EmptyState
                icon={<Server className="size-5" />}
                title="No named assets"
                description="Every finding in this report is about a submitted artifact rather than a host, so there is nothing to rank by asset."
              />
            ) : (
              <ul className="divide-y divide-border-subtle">
                {topAssets.map((entry) => (
                  <li
                    key={entry.asset}
                    className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3"
                  >
                    <SeverityBadge severity={entry.worst as Severity} size="sm" />
                    <Link
                      href={`/findings?q=${encodeURIComponent(entry.asset)}`}
                      className="min-w-0 flex-1 truncate font-mono text-body-sm text-text-primary transition-colors hover:text-accent"
                      title={entry.asset}
                    >
                      {entry.asset}
                    </Link>
                    <SeverityTally counts={entry.counts} order={SEVERITY_ORDER} />
                    <span className="shrink-0 font-mono text-caption text-text-tertiary">
                      <span data-numeric>{entry.count}</span> total
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <p className="mt-6 text-caption text-text-tertiary">
            Generated {new Date().toLocaleString()} from{' '}
            <span data-numeric>{findings.length}</span> finding
            {findings.length === 1 ? '' : 's'}
            {capped ? ` of ${total} recorded` : ''}. No figure on this page is estimated or
            model-generated.
          </p>
        </>
      )}
    </>
  )
}

/** Widen an untrusted severity tally to the full five keys, dropping anything unrecognised. */
function fillCounts(severities: Record<string, number>): Record<Severity, number> {
  const counts = emptySeverityCounts()
  for (const severity of SEVERITY_ORDER) counts[severity] = severities[severity] ?? 0
  return counts
}
