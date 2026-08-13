'use client'

import Link from 'next/link'
import { useMemo, useState } from 'react'

import { AgentTrace, readAgentTrace } from '@/components/findings/AgentTrace'
import { Badge, Dot, SeverityBadge, SeverityTally } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardFooter, CardHeader } from '@/components/ui/Card'
import { SeverityBarChart, TrendAreaChart } from '@/components/ui/charts'
import {
  AGENT_ICON,
  Activity,
  ArrowRight,
  Layers,
  Play,
  Radar,
  ShieldAlert,
} from '@/components/ui/icons'
import { PageHeader, SectionHeader } from '@/components/ui/PageHeader'
import { StatCard, StatGrid } from '@/components/ui/StatCard'
import {
  EmptyState,
  InlineError,
  StatGridSkeleton,
  TableSkeleton,
} from '@/components/ui/states'
import { OPEN_STATUSES, byPriority, readAssetRanking } from '@/lib/findings'
import {
  useCreateRun,
  useFindings,
  useRunAgent,
  useRuns,
  useSystemModules,
  useUpdateRun,
} from '@/lib/queries'
import { SEVERITY_ORDER, SEVERITY_WEIGHT, emptySeverityCounts } from '@/lib/severity'
import { cn } from '@/lib/utils'
import type { Finding, RunRead, Severity } from '@/types'

/**
 * Security posture, at a glance.
 *
 * The question this page answers is "what should I look at first", so it is ordered by that
 * and nothing else: exposure totals, then what is worst, then which assets carry it, then
 * what the platform has been doing. Everything below the top row is a link into the view
 * where the work actually happens.
 *
 * Two rules held throughout:
 *
 * **Open findings only.** A resolved finding has been dealt with, and counting it as exposure
 * is how a dashboard keeps reporting work that is already done.
 *
 * **Nothing is invented.** Every number is computed from findings the backend returned. The
 * trend is real observation dates, and where the fetch is capped the page says so rather than
 * presenting a partial count as a total.
 */

/** Days of history in the trend. Two weeks reads as a trend; a week reads as noise. */
const TREND_DAYS = 14

/** How many findings the dashboard reads. Also the cap the page discloses. */
const FINDINGS_LIMIT = 200

export default function DashboardPage() {
  const findingsQuery = useFindings({ limit: FINDINGS_LIMIT })
  const runsQuery = useRuns(6)
  const modulesQuery = useSystemModules()

  /* Memoised because `?? []` allocates a fresh array on every render, and every `useMemo`
     below depends on it — without this, none of them ever hit their cache. */
  const findings = useMemo(() => findingsQuery.data?.items ?? [], [findingsQuery.data])
  const total = findingsQuery.data?.total ?? 0
  const capped = total > findings.length

  const stats = useMemo(() => {
    const counts = emptySeverityCounts()
    const byAgent = new Map<string, number>()
    const open = findings.filter((finding) => OPEN_STATUSES.includes(finding.status))
    for (const finding of open) {
      counts[finding.severity] += 1
      byAgent.set(finding.agent, (byAgent.get(finding.agent) ?? 0) + 1)
    }
    return { counts, byAgent, open: open.length }
  }, [findings])

  /** Real observation dates bucketed by day. Empty days are present so gaps show as gaps. */
  const trend = useMemo(() => buildTrend(findings, TREND_DAYS), [findings])

  /** Ranked by the ai.engine on each asset's single worst finding, not on volume:
   *  ten mediums are a backlog, one critical is an incident. */
  const assetRanking = useMemo(() => readAssetRanking(findings).slice(0, 6), [findings])

  const needsAttention = useMemo(
    () =>
      findings
        .filter((finding) => OPEN_STATUSES.includes(finding.status))
        .sort(byPriority(SEVERITY_WEIGHT))
        .slice(0, 6),
    [findings],
  )

  const traced = useMemo(
    () =>
      findings
        .map((finding) => ({ finding, trace: readAgentTrace(finding.evidence) }))
        .filter((entry) => entry.trace.length > 0)
        .slice(0, 2),
    [findings],
  )

  const modules = modulesQuery.data?.items ?? []
  const modulesDown = modules.filter((module) => module.status !== 'ok')

  return (
    <>
      <PageHeader
        title="Security posture"
        description="Open exposure across every agent, worst first. Numbers count findings that still need an analyst — resolved and dismissed findings are excluded."
        actions={<QuickScan onFinished={() => void findingsQuery.refetch()} />}
      />

      {findingsQuery.error ? (
        <InlineError
          error={findingsQuery.error}
          onRetry={() => void findingsQuery.refetch()}
          className="mb-4"
        />
      ) : null}

      {modulesDown.length > 0 ? (
        <div
          role="status"
          className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-md border border-status-warn/30 bg-status-warn-bg px-3.5 py-2.5"
        >
          <p className="text-body-sm text-text-primary">
            <span className="font-medium">
              {modulesDown.length} module{modulesDown.length === 1 ? '' : 's'} unreachable
            </span>
            <span className="text-text-secondary">
              {' — '}
              {modulesDown.map((module) => module.name).join(', ')}. Findings may be
              incomplete until they recover.
            </span>
          </p>
          <Button size="sm" variant="secondary" href="/services">
            Check services
          </Button>
        </div>
      ) : null}

      {findingsQuery.isPending ? (
        <StatGridSkeleton count={4} />
      ) : (
        <StatGrid>
          <StatCard
            label="Open findings"
            value={stats.open}
            hint={
              capped
                ? `of ${total} recorded — showing the newest ${findings.length}`
                : 'across every agent'
            }
            icon={<Layers className="size-4" />}
            href="/findings"
          />
          <StatCard
            label="Critical"
            value={stats.counts.critical}
            tone="critical"
            hint={
              stats.open > 0
                ? `${Math.round((stats.counts.critical / stats.open) * 100)}% of open exposure`
                : 'nothing open'
            }
            icon={<ShieldAlert className="size-4" />}
            href="/findings?severity=critical"
          />
          <StatCard
            label="High"
            value={stats.counts.high}
            tone="high"
            hint="next after critical"
            icon={<Activity className="size-4" />}
            href="/findings?severity=high"
          />
          <StatCard
            label="Agents reporting"
            value={stats.byAgent.size}
            tone={stats.byAgent.size > 0 ? 'accent' : 'default'}
            hint="of 4 detection agents"
            icon={<Radar className="size-4" />}
          />
        </StatGrid>
      )}

      <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <Card>
          <CardHeader
            title="By severity"
            description="Open findings only."
            actions={
              <Button size="sm" variant="ghost" href="/findings">
                Filter
              </Button>
            }
          />
          <CardBody>
            <SeverityBarChart counts={stats.counts} height={196} />
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title={`Detections, last ${TREND_DAYS} days`}
            description={
              capped
                ? `From the newest ${findings.length} findings, so earlier days may be undercounted.`
                : 'Every finding, by the day it was observed.'
            }
          />
          <CardBody>
            <TrendAreaChart data={trend} height={196} />
          </CardBody>
        </Card>
      </div>

      <SectionHeader
        className="mt-8"
        title="Needs attention"
        description="Ranked by the rule engine's remediation score where there is one, then by severity."
        actions={
          <Button
            size="sm"
            variant="ghost"
            href="/findings"
            trailingIcon={<ArrowRight className="size-3.5" />}
          >
            All findings
          </Button>
        }
      />
      <Card>
        {findingsQuery.isPending ? (
          <TableSkeleton rows={5} columns={3} />
        ) : needsAttention.length === 0 ? (
          <EmptyState
            icon={<Radar className="size-5" />}
            title={total === 0 ? 'Nothing detected yet' : 'Nothing open'}
            description={
              total === 0
                ? 'Upload a scanner report or submit a suspect message and the agents will populate this page.'
                : 'Every finding has been resolved or dismissed. New detections will appear here.'
            }
            action={
              total === 0 ? (
                <div className="flex flex-wrap justify-center gap-2">
                  <Button href="/scans" variant="primary">
                    Upload a scan
                  </Button>
                  <Button href="/phishing" variant="secondary">
                    Analyse a message
                  </Button>
                </div>
              ) : null
            }
          />
        ) : (
          <ul className="divide-y divide-border-subtle">
            {needsAttention.map((finding) => (
              <FindingRow key={finding.id} finding={finding} />
            ))}
          </ul>
        )}
      </Card>

      {assetRanking.length > 0 ? (
        <>
          <SectionHeader
            className="mt-8"
            title="Riskiest assets"
            description="Ranked on each asset's single worst finding rather than how many it has, so one critical outranks a long tail of lows. Scored deterministically by the ai.engine."
          />
          <Card>
            <ul className="divide-y divide-border-subtle">
              {assetRanking.map((risk) => (
                <li
                  key={risk.asset}
                  className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3"
                >
                  <SeverityBadge severity={risk.worst_severity} size="sm" />
                  <Link
                    href={`/findings?q=${encodeURIComponent(risk.asset)}`}
                    className="min-w-0 flex-1 truncate font-mono text-body-sm text-text-primary transition-colors hover:text-accent"
                    title={risk.asset}
                  >
                    {risk.asset}
                  </Link>
                  <SeverityTally
                    counts={toSeverityCounts(risk.severities)}
                    order={SEVERITY_ORDER}
                  />
                  <span className="font-mono text-caption whitespace-nowrap text-text-tertiary">
                    worst{' '}
                    <span className="text-accent" data-numeric>
                      {Math.round(risk.top_score)}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          </Card>
        </>
      ) : null}

      <div className="mt-8 grid gap-4 lg:grid-cols-2">
        <Card className="flex flex-col">
          <CardHeader
            title="Coverage by agent"
            description="Open findings each agent is currently reporting."
          />
          <CardBody className="flex-1">
            {stats.byAgent.size === 0 ? (
              <p className="text-body-sm text-text-tertiary">
                No agent has reported an open finding yet.
              </p>
            ) : (
              <ul className="space-y-2.5">
                {[...stats.byAgent.entries()]
                  .sort((a, b) => b[1] - a[1])
                  .map(([agent, count]) => {
                    const Icon = AGENT_ICON[agent as keyof typeof AGENT_ICON] ?? Radar
                    const share = stats.open > 0 ? (count / stats.open) * 100 : 0
                    return (
                      <li key={agent} className="flex items-center gap-3">
                        <span className="flex w-32 shrink-0 items-center gap-2 text-body-sm capitalize text-text-secondary">
                          <Icon className="size-3.5 text-text-tertiary" aria-hidden />
                          {agent}
                        </span>
                        <span className="h-1.5 min-w-8 flex-1 overflow-hidden rounded-full bg-surface-sunken">
                          <span
                            className="block h-full rounded-full bg-accent"
                            style={{ width: `${share}%` }}
                          />
                        </span>
                        <span
                          className="w-8 shrink-0 text-right font-mono text-caption text-text-secondary"
                          data-numeric
                        >
                          {count}
                        </span>
                      </li>
                    )
                  })}
              </ul>
            )}
          </CardBody>
        </Card>

        <Card className="flex flex-col">
          <CardHeader
            title="Recent pipeline runs"
            actions={
              <Button size="sm" variant="ghost" href="/run">
                Run agents
              </Button>
            }
          />
          {runsQuery.isPending ? (
            <TableSkeleton rows={4} columns={2} />
          ) : runsQuery.error ? (
            <CardBody>
              <InlineError error={runsQuery.error} onRetry={() => void runsQuery.refetch()} />
            </CardBody>
          ) : (runsQuery.data?.items.length ?? 0) === 0 ? (
            <EmptyState
              icon={<Play className="size-5" />}
              title="No runs yet"
              description="Launch the pipeline against a target and each agent's progress is recorded here."
              action={
                <Button href="/run" variant="secondary">
                  Open the runner
                </Button>
              }
            />
          ) : (
            <ul className="flex-1 divide-y divide-border-subtle">
              {runsQuery.data?.items.map((run) => <RunRow key={run.id} run={run} />)}
            </ul>
          )}
        </Card>
      </div>

      {traced.length > 0 ? (
        <>
          <SectionHeader
            className="mt-8"
            title="What the agents did"
            description="The tool calls behind recent findings — the audit trail for whether an agent looked or guessed."
          />
          <div className="grid gap-4 lg:grid-cols-2">
            {traced.map(({ finding, trace }) => (
              <Card key={finding.id}>
                <CardHeader
                  title={
                    <span className="flex min-w-0 items-center gap-2">
                      <Badge tone="neutral" size="sm" className="capitalize">
                        {finding.agent}
                      </Badge>
                      <span className="truncate">{finding.title}</span>
                    </span>
                  }
                />
                <CardBody>
                  <AgentTrace entries={trace} />
                </CardBody>
                <CardFooter>
                  <span className="text-caption text-text-tertiary">
                    <span data-numeric>{trace.length}</span> trace entries
                  </span>
                  <Button size="sm" variant="ghost" href={`/findings/${finding.id}`}>
                    Open finding
                  </Button>
                </CardFooter>
              </Card>
            ))}
          </div>
        </>
      ) : null}

      <SectionHeader
        className="mt-8"
        title="Platform"
        description="Each module the platform depends on, checked from the backend."
        actions={
          <Button
            size="sm"
            variant="ghost"
            onClick={() => void modulesQuery.refetch()}
            loading={modulesQuery.isFetching}
          >
            Check again
          </Button>
        }
      />
      <Card>
        <CardBody>
          {modulesQuery.error ? (
            <InlineError
              error={modulesQuery.error}
              onRetry={() => void modulesQuery.refetch()}
            />
          ) : modulesQuery.isPending ? (
            <TableSkeleton rows={3} columns={2} />
          ) : (
            <ul className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
              {modules.map((module) => (
                <li
                  key={module.name}
                  className="flex items-center justify-between gap-3 rounded-md border border-border-subtle bg-surface-sunken px-3 py-2"
                >
                  <span className="flex min-w-0 items-center gap-2">
                    <Dot tone={module.status === 'ok' ? 'ok' : 'error'} />
                    <span className="truncate text-body-sm font-medium text-text-primary">
                      {module.name}
                    </span>
                  </span>
                  <span
                    className="truncate font-mono text-caption text-text-tertiary"
                    title={module.detail || undefined}
                  >
                    {module.host}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardBody>
      </Card>
    </>
  )
}

/* ------------------------------------------------------------------- rows */

function FindingRow({ finding }: { finding: Finding }) {
  const Icon = AGENT_ICON[finding.agent] ?? Radar
  return (
    <li>
      <Link
        href={`/findings/${finding.id}`}
        className="flex items-center gap-3 px-4 py-3 transition-colors duration-(--duration-fast) hover:bg-surface-raised-hover"
      >
        <SeverityBadge severity={finding.severity} size="sm" className="shrink-0" />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-body-sm font-medium text-text-primary">
            {finding.title}
          </span>
          <span className="mt-0.5 block truncate font-mono text-caption text-text-tertiary">
            {finding.asset ?? finding.source} · {formatWhen(finding.detected_at)}
          </span>
        </span>
        <span className="hidden shrink-0 items-center gap-1.5 text-caption capitalize text-text-tertiary sm:flex">
          <Icon className="size-3.5" aria-hidden />
          {finding.agent}
        </span>
      </Link>
    </li>
  )
}

const RUN_TONE = {
  running: 'active',
  completed: 'ok',
  completed_with_errors: 'warn',
  failed: 'error',
} as const

const RUN_LABEL = {
  running: 'Running',
  completed: 'Completed',
  completed_with_errors: 'Completed with errors',
  failed: 'Failed',
} as const

function RunRow({ run }: { run: RunRead }) {
  const agents = Object.values(run.agent_statuses ?? {})
  const findings = agents.reduce((sum, snapshot) => sum + (snapshot.count ?? 0), 0)
  const done = agents.filter((snapshot) => snapshot.state === 'done').length

  return (
    <li>
      <Link
        href="/run"
        className="flex items-center gap-3 px-4 py-3 transition-colors duration-(--duration-fast) hover:bg-surface-raised-hover"
      >
        <Badge
          tone={RUN_TONE[run.status]}
          size="sm"
          className="shrink-0"
          icon={<Dot tone={RUN_TONE[run.status]} pulse={run.status === 'running'} />}
        >
          {RUN_LABEL[run.status]}
        </Badge>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-body-sm font-medium text-text-primary">
            {runTargetLabel(run.target)}
          </span>
          <span className="mt-0.5 block text-caption text-text-tertiary">
            <span data-numeric>{done}</span> agent{done === 1 ? '' : 's'} ·{' '}
            <span data-numeric>{findings}</span> finding{findings === 1 ? '' : 's'} ·{' '}
            {formatWhen(run.created_at)}
          </span>
        </span>
      </Link>
    </li>
  )
}

/* ------------------------------------------------------------- quick scan */

/**
 * One-click discovery of the local network.
 *
 * Kept on the dashboard rather than moved into Analyse as the plan sketched: an overview whose
 * only affordances are navigation is a dead end, and `/run` already owns the *configured*
 * run. This is the unconfigured one — create a run, point the network agent at whatever it
 * finds, record the result.
 *
 * The three calls are sequential and each one matters, so the states are explicit rather than
 * collapsed into one boolean. A failure names which step failed.
 */
function QuickScan({ onFinished }: { onFinished: () => void }) {
  const createRun = useCreateRun()
  const runAgent = useRunAgent()
  const updateRun = useUpdateRun()

  const [error, setError] = useState<string | null>(null)
  const busy = createRun.isPending || runAgent.isPending || updateRun.isPending

  async function start() {
    setError(null)
    try {
      const run = await createRun.mutateAsync({ target: 'quick', mode: 'auto' })
      const response = await runAgent.mutateAsync({
        agent: 'network',
        payload: {
          source: 'auto',
          asset: '',
          raw_input: '',
          background: false,
          persist: true,
          run_id: run.id,
        },
      })
      await updateRun.mutateAsync({
        id: run.id,
        payload: {
          status: 'completed',
          agent_statuses: {
            vulnerability: { state: 'skipped', count: 0 },
            phishing: { state: 'skipped', count: 0 },
            network: { state: 'done', count: response.findings?.length ?? 0 },
            webapp: { state: 'skipped', count: 0 },
          },
        },
      })
      onFinished()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The quick scan could not be started.')
    }
  }

  return (
    <div className="flex flex-col items-end gap-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="secondary" href="/run">
          Configure a run
        </Button>
        <Button
          variant="primary"
          leadingIcon={<Play className="size-4" />}
          loading={busy}
          onClick={() => void start()}
        >
          {busy ? 'Scanning…' : 'Quick scan'}
        </Button>
      </div>
      {error ? (
        <p className={cn('max-w-xs text-right text-caption text-severity-critical')} role="alert">
          {error}
        </p>
      ) : null}
    </div>
  )
}

/* ---------------------------------------------------------------- helpers */

/**
 * Narrow the ai.engine's per-severity tallies to the severities this build knows.
 *
 * The ranking blob is untrusted in shape — `readAssetRanking` guarantees the values are
 * numbers, not which keys are present — so an unrecognised key is dropped rather than
 * rendered as an unnamed sixth severity.
 */
function toSeverityCounts(severities: Record<string, number>): Record<Severity, number> {
  const counts = emptySeverityCounts()
  for (const severity of SEVERITY_ORDER) {
    counts[severity] = severities[severity] ?? 0
  }
  return counts
}

/**
 * Findings bucketed by observation day, oldest first.
 *
 * Every day in the window is emitted, including empty ones, so a gap in detection reads as a
 * flat stretch rather than being compressed away by the x-axis.
 */
function buildTrend(findings: readonly Finding[], days: number) {
  const buckets = new Map<string, Record<Severity, number>>()
  const today = new Date()
  today.setHours(0, 0, 0, 0)

  for (let offset = days - 1; offset >= 0; offset -= 1) {
    const day = new Date(today)
    day.setDate(day.getDate() - offset)
    buckets.set(dayKey(day), emptySeverityCounts())
  }

  for (const finding of findings) {
    const observed = new Date(finding.detected_at)
    if (Number.isNaN(observed.getTime())) continue
    const bucket = buckets.get(dayKey(observed))
    if (bucket) bucket[finding.severity] += 1
  }

  return [...buckets.entries()].map(([key, counts]) => ({
    date: key.slice(5).replace('-', '/'),
    critical: counts.critical,
    high: counts.high,
    medium: counts.medium,
    low: counts.low,
    info: counts.info,
  }))
}

/** Local calendar day, so bucketing matches what the analyst's clock says. */
function dayKey(date: Date): string {
  const month = `${date.getMonth() + 1}`.padStart(2, '0')
  const day = `${date.getDate()}`.padStart(2, '0')
  return `${date.getFullYear()}-${month}-${day}`
}

function formatWhen(iso: string): string {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return 'unknown'
  const minutes = Math.floor((Date.now() - then) / 60_000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

function runTargetLabel(target: string): string {
  if (target.startsWith('email:')) return `Email scan · ${target.slice('email:'.length)}`
  if (target === 'quick') return 'Quick auto-scan'
  return target
}
