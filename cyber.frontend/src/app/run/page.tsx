'use client'

import Link from 'next/link'
import { useCallback, useRef, useState } from 'react'

import { Badge, Dot, SeverityBadge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardFooter, CardHeader, Well } from '@/components/ui/Card'
import { Checkbox, Field, Input } from '@/components/ui/Field'
import {
  AGENT_ICON,
  ArrowRight,
  Check,
  ChevronRight,
  CircleDashed,
  CircleX,
  Globe,
  Loader2,
  MinusCircle,
  Network,
  Play,
  Radar,
  Server,
  Waypoints,
} from '@/components/ui/icons'
import { KeyValueList } from '@/components/ui/KeyValueList'
import { PageHeader, SectionHeader, Eyebrow } from '@/components/ui/PageHeader'
import { EmptyState, InlineError } from '@/components/ui/states'
import { updateRun } from '@/lib/api'
import { bySeverity } from '@/lib/findings'
import { useCreateRun, useLatestRun, useRunAgent, useRunDiscovery } from '@/lib/queries'
import { cn } from '@/lib/utils'
import type {
  AgentKind,
  AgentStatusSnapshot,
  DiscoveryReport,
  Finding,
  RunStatus,
  RunUpdate,
} from '@/types'

/**
 * The browser-driven pipeline runner.
 *
 * Honest about what it is: this page orchestrates from the browser. It creates a run row, calls
 * discovery, fans out to the selected agents, and PATCHes progress back so a refresh does not
 * lose the picture. That is different from `/scans`, where the server owns the whole job — both
 * are kept because both are reachable capabilities, and the overlap is a product decision this
 * redesign does not get to make.
 *
 * **Two controls were dead before this rewrite** and are now live rather than removed:
 *
 * `pipelineAgents` had a setter that nothing ever called, so *manual* mode always selected zero
 * agents and pressing Run did nothing. Manual mode now has real checkboxes.
 *
 * `mailSource` had the same problem, and it gated the phishing agent — so auto mode always
 * skipped it. The mailbox integration that field referred to was removed along with the
 * plaintext secret store, and the phishing agent does not need it: pointed at a domain it runs
 * SPF/DKIM/DMARC and URL checks. The gate is gone.
 */

interface AgentDef {
  kind: AgentKind
  name: string
  tool: string
  description: string
}

/** All four agents scan the target themselves — there is no scanner output to paste. */
const AGENTS: readonly AgentDef[] = [
  {
    kind: 'vulnerability',
    name: 'Vulnerability assessment',
    tool: 'nmap',
    description: 'Scans the host and correlates open services with known CVEs.',
  },
  {
    kind: 'webapp',
    name: 'Web application',
    tool: 'nuclei',
    description: 'Scans the URL and maps alerts onto the OWASP Top 10.',
  },
  {
    kind: 'network',
    name: 'Network traffic',
    tool: 'ss snapshot',
    description: 'Takes a live TCP snapshot and looks for anomalies.',
  },
  {
    kind: 'phishing',
    name: 'Phishing checks',
    tool: 'DNS + HTTP',
    description: 'Runs SPF, DKIM and DMARC lookups plus URL checks against the target.',
  },
]

const ALL_KINDS = AGENTS.map((agent) => agent.kind)

const EMPTY_STATUSES: Record<AgentKind, AgentStatusSnapshot> = {
  vulnerability: { state: 'pending', count: 0 },
  phishing: { state: 'pending', count: 0 },
  network: { state: 'pending', count: 0 },
  webapp: { state: 'pending', count: 0 },
}

const STATE_META = {
  pending: { Icon: CircleDashed, tone: 'text-text-tertiary', label: 'Queued' },
  running: { Icon: Loader2, tone: 'text-accent', label: 'Scanning' },
  done: { Icon: Check, tone: 'text-status-ok', label: 'Done' },
  error: { Icon: CircleX, tone: 'text-status-error', label: 'Failed' },
  skipped: { Icon: MinusCircle, tone: 'text-text-tertiary', label: 'Skipped' },
} as const

export default function RunPipelinePage() {
  const [target, setTarget] = useState('')
  const [mode, setMode] = useState<'auto' | 'manual'>('auto')
  const [picked, setPicked] = useState<AgentKind[]>([...ALL_KINDS])

  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [discoveryError, setDiscoveryError] = useState<string | null>(null)

  const [statuses, setStatuses] = useState<Record<AgentKind, AgentStatusSnapshot> | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [discovery, setDiscovery] = useState<DiscoveryReport | null>(null)
  const [runId, setRunId] = useState<string | null>(null)
  const [runStatus, setRunStatus] = useState<RunStatus | null>(null)
  const [restoredFrom, setRestoredFrom] = useState<string | null>(null)

  const createRun = useCreateRun()
  const runAgent = useRunAgent()
  const discover = useRunDiscovery()

  // A ref as well as state: the PATCH helper is called from inside an async run, where the
  // state value captured at closure time would be one render stale.
  const runIdRef = useRef<string | null>(null)

  /** Best-effort persistence. A lost PATCH costs the refresh-survives property, not the run. */
  const persist = useCallback((patch: RunUpdate) => {
    const id = runIdRef.current
    if (!id) return
    void updateRun(id, patch).catch(() => undefined)
  }, [])

  /* Restore the last run so a refresh mid-pipeline does not lose the picture. `retry: false`
     on the hook because a 404 means "no run yet", which is a normal state. */
  const latest = useLatestRun()
  const restorable = latest.data
  const canRestore = restorable && restorable.id !== runId && !running

  function restore() {
    if (!restorable) return
    runIdRef.current = restorable.id
    setRunId(restorable.id)
    setRunStatus(restorable.status)
    setTarget(restorable.target)
    setMode(restorable.mode)
    setDiscovery(restorable.discovery)
    setStatuses(restorable.agent_statuses)
    // Findings are not restored: the run row stores counts, not the findings themselves.
    // They are one click away in /findings, which is where the durable copy lives.
    setFindings([])
    setRestoredFrom(restorable.id)
  }

  const selected = mode === 'manual' ? AGENTS.filter((a) => picked.includes(a.kind)) : AGENTS
  const skipped = AGENTS.filter((a) => !selected.some((s) => s.kind === a.kind))

  async function start(event: React.FormEvent) {
    event.preventDefault()
    const asset = target.trim()
    if (!asset || running || selected.length === 0) return

    setRunning(true)
    setError(null)
    setDiscoveryError(null)
    setDiscovery(null)
    setFindings([])
    setRestoredFrom(null)

    let currentRunId: string
    try {
      const run = await createRun.mutateAsync({ target: asset, mode })
      currentRunId = run.id
      runIdRef.current = run.id
      setRunId(run.id)
      setRunStatus('running')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not create the run.')
      setRunning(false)
      return
    }

    // Phase 1 — discovery. A failure here is reported and does not stop the agents: they scan
    // the given target directly and do not depend on what discovery found.
    const initial = { ...EMPTY_STATUSES }
    for (const kind of ALL_KINDS) {
      initial[kind] = selected.some((a) => a.kind === kind)
        ? { state: 'pending', count: 0 }
        : { state: 'skipped', count: 0 }
    }
    setStatuses(initial)
    persist({ agent_statuses: initial })

    try {
      const report = await discover.mutateAsync()
      setDiscovery(report)
      persist({ discovery: report })
    } catch (cause) {
      setDiscoveryError(cause instanceof Error ? cause.message : 'Discovery failed.')
    }

    // Phase 2 — fan out. Each agent's status flips as its own request settles, so the slowest
    // agent does not hold back the display of the fastest.
    const withRunning = { ...initial }
    for (const agent of selected) withRunning[agent.kind] = { state: 'running', count: 0 }
    setStatuses(withRunning)
    persist({ agent_statuses: withRunning })

    const settled = { ...withRunning }
    const commit = (kind: AgentKind, snapshot: AgentStatusSnapshot) => {
      settled[kind] = snapshot
      setStatuses({ ...settled })
      persist({ agent_statuses: { ...settled } })
    }

    const results = await Promise.all(
      selected.map(async ({ kind }) => {
        try {
          const response = await runAgent.mutateAsync({
            agent: kind,
            payload: {
              source: 'auto',
              asset,
              raw_input: '',
              background: false,
              persist: true,
              run_id: currentRunId,
            },
          })
          const produced = response.findings ?? []
          setFindings((current) => [...current, ...produced])
          commit(kind, { state: 'done', count: produced.length })
          return true
        } catch (cause) {
          commit(kind, {
            state: 'error',
            count: 0,
            error: cause instanceof Error ? cause.message : 'Unknown error',
          })
          return false
        }
      }),
    )

    const final: RunStatus = results.some((ok) => !ok) ? 'completed_with_errors' : 'completed'
    setRunStatus(final)
    persist({ status: final })
    setRunning(false)
  }

  const totalFindings = Object.values(statuses ?? {}).reduce(
    (sum, snapshot) => sum + snapshot.count,
    0,
  )

  return (
    <>
      <PageHeader
        title="Run agents"
        description="Give the pipeline a target. Discovery maps what is reachable, then each selected agent scans the target itself — there is no scanner output to paste."
        meta={
          runStatus ? (
            <Badge
              tone={
                runStatus === 'running'
                  ? 'active'
                  : runStatus === 'completed'
                    ? 'ok'
                    : runStatus === 'completed_with_errors'
                      ? 'warn'
                      : 'error'
              }
              icon={<Dot tone={runStatus === 'running' ? 'active' : 'ok'} pulse={running} />}
            >
              {runStatus === 'running'
                ? 'Running'
                : runStatus === 'completed'
                  ? 'Completed'
                  : runStatus === 'completed_with_errors'
                    ? 'Completed with errors'
                    : 'Failed'}
            </Badge>
          ) : null
        }
      />

      {canRestore ? (
        <Well className="mb-4 flex flex-wrap items-center justify-between gap-3 py-2.5">
          <p className="text-body-sm text-text-secondary">
            The last run against{' '}
            <span className="font-mono text-text-primary">{restorable.target}</span> is still on
            record.
          </p>
          <Button size="sm" variant="secondary" onClick={restore}>
            Load it
          </Button>
        </Well>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,24rem)_minmax(0,1fr)] lg:items-start">
        <form onSubmit={start} className="space-y-4">
          <Card>
            <CardHeader title="Target" />
            <CardBody className="space-y-4">
              <Field
                label="Host, IP, range, URL or domain"
                hint="One host like 10.0.0.20, or a whole network like 192.168.1.0/24."
              >
                <Input
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder="10.0.0.20 or 192.168.1.0/24"
                  required
                  disabled={running}
                />
              </Field>

              {/* A range is discovered first and only the live hosts are scanned, so the
                  cost is the machines that exist rather than the size of the range. Worth
                  saying here: a /24 finishing in minutes is otherwise surprising. */}
              {target.includes('/') ? (
                <p className="text-caption text-text-tertiary">
                  A range is swept in two passes — find which addresses answer, then scan
                  only those. The whole range must be authorised under{' '}
                  <Link href="/scope" className="text-accent hover:underline">
                    Scan scope
                  </Link>{' '}
                  first, and a sweep is visible to any monitoring on the network.
                </p>
              ) : null}

              <div>
                <Eyebrow>Which agents</Eyebrow>
                <div
                  role="group"
                  aria-label="Agent selection mode"
                  className="mt-1.5 grid grid-cols-2 gap-1 rounded-md border border-border-default p-1"
                >
                  {(
                    [
                      { value: 'auto', label: 'All four' },
                      { value: 'manual', label: 'Choose' },
                    ] as const
                  ).map((option) => (
                    <button
                      key={option.value}
                      type="button"
                      aria-pressed={mode === option.value}
                      disabled={running}
                      onClick={() => setMode(option.value)}
                      className={cn(
                        'rounded-sm px-2 py-1.5 text-body-sm font-medium',
                        'transition-colors duration-(--duration-fast)',
                        mode === option.value
                          ? 'bg-accent-surface text-accent'
                          : 'text-text-tertiary hover:bg-surface-raised-hover hover:text-text-secondary',
                      )}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
              </div>

              {mode === 'manual' ? (
                <div className="space-y-2.5">
                  {AGENTS.map((agent) => (
                    <Checkbox
                      key={agent.kind}
                      checked={picked.includes(agent.kind)}
                      disabled={running}
                      onChange={(event) =>
                        setPicked((current) =>
                          event.target.checked
                            ? [...current, agent.kind]
                            : current.filter((kind) => kind !== agent.kind),
                        )
                      }
                      label={agent.name}
                      description={agent.description}
                    />
                  ))}
                  {selected.length === 0 ? (
                    <p className="text-caption text-severity-medium">
                      Nothing selected — pick at least one agent.
                    </p>
                  ) : null}
                </div>
              ) : (
                <ul className="space-y-1.5">
                  {AGENTS.map((agent) => {
                    const Icon = AGENT_ICON[agent.kind]
                    return (
                      <li
                        key={agent.kind}
                        className="flex items-center gap-2 text-body-sm text-text-secondary"
                      >
                        <Icon className="size-3.5 shrink-0 text-text-tertiary" aria-hidden />
                        <span className="min-w-0 flex-1 truncate">{agent.name}</span>
                        <span className="shrink-0 font-mono text-caption text-text-tertiary">
                          {agent.tool}
                        </span>
                      </li>
                    )
                  })}
                </ul>
              )}

              {error ? (
                <div className="space-y-2">
                  <InlineError error={error} />
                  {/* The backend's refusal already names the exact range to authorise, so
                      the only thing missing is somewhere to do it. Matched on the phrase
                      the target policy uses rather than on a status code, because the
                      refusal arrives as an agent result, not as an HTTP error. */}
                  {/scope|authorised range|allowlist/i.test(error) ? (
                    <Button size="sm" variant="secondary" href="/scope">
                      Authorise this range
                    </Button>
                  ) : null}
                </div>
              ) : null}
            </CardBody>
            <CardFooter>
              <p className="text-caption text-text-tertiary">
                <span data-numeric>{selected.length}</span> agent
                {selected.length === 1 ? '' : 's'} will run
                {skipped.length > 0 ? `, ${skipped.length} skipped` : ''}
              </p>
              <Button
                type="submit"
                variant="primary"
                leadingIcon={<Play className="size-4" />}
                loading={running}
                disabled={!target.trim() || selected.length === 0}
              >
                {running ? 'Running…' : 'Run pipeline'}
              </Button>
            </CardFooter>
          </Card>
        </form>

        <div className="space-y-4">
          {statuses === null ? (
            <Card>
              <CardBody>
                <EmptyState
                  icon={<Radar className="size-5" />}
                  title="No run in progress"
                  description="Enter a target and press Run pipeline. Discovery runs first, then each agent reports here as its own scan settles."
                />
              </CardBody>
            </Card>
          ) : (
            <Card>
              <CardHeader
                title="Agents"
                description={
                  restoredFrom
                    ? `Restored from run ${restoredFrom.slice(0, 8)} — counts are from the stored run, not this session.`
                    : undefined
                }
                actions={
                  <span className="text-caption text-text-tertiary">
                    <span data-numeric>{totalFindings}</span> finding
                    {totalFindings === 1 ? '' : 's'}
                  </span>
                }
              />
              <ul className="divide-y divide-border-subtle">
                {AGENTS.map((agent) => {
                  const snapshot = statuses[agent.kind]
                  const meta = STATE_META[snapshot.state]
                  const AgentIcon = AGENT_ICON[agent.kind]
                  return (
                    <li key={agent.kind} className="flex items-start gap-3 px-4 py-3">
                      <meta.Icon
                        className={cn(
                          'mt-0.5 size-4 shrink-0',
                          meta.tone,
                          snapshot.state === 'running' &&
                            'animate-spin motion-reduce:animate-none',
                        )}
                        aria-hidden
                      />
                      <div className="min-w-0 flex-1">
                        <p
                          className={cn(
                            'flex items-center gap-2 text-body-sm font-medium',
                            snapshot.state === 'skipped'
                              ? 'text-text-tertiary'
                              : 'text-text-primary',
                          )}
                        >
                          <AgentIcon
                            className="size-3.5 shrink-0 text-text-tertiary"
                            aria-hidden
                          />
                          {agent.name}
                        </p>
                        <p className="mt-0.5 text-caption text-text-tertiary">
                          {agent.tool} · {meta.label}
                          {snapshot.state === 'done'
                            ? ` · ${snapshot.count} finding${snapshot.count === 1 ? '' : 's'}`
                            : ''}
                        </p>
                        {snapshot.state === 'error' ? (
                          <p className="mt-1 text-caption text-severity-critical">
                            {snapshot.error ?? 'No reason recorded.'}
                          </p>
                        ) : null}
                      </div>
                    </li>
                  )
                })}
              </ul>
              {runStatus && runStatus !== 'running' ? (
                <CardFooter>
                  <span className="text-caption text-text-tertiary">
                    Run <span className="font-mono">{runId?.slice(0, 8)}</span>
                  </span>
                  <Button
                    size="sm"
                    variant="secondary"
                    href="/findings"
                    trailingIcon={<ArrowRight className="size-3.5" />}
                  >
                    All findings
                  </Button>
                </CardFooter>
              ) : null}
            </Card>
          )}

          {discoveryError ? (
            <InlineError error={`Discovery failed: ${discoveryError}`} />
          ) : null}

          {discovery ? <DiscoveryPanel report={discovery} /> : null}

          {findings.length > 0 ? (
            <>
              <SectionHeader
                title="What this run found"
                description="Already persisted — these are links into the findings queue, not a temporary list."
              />
              <Card>
                <ul className="divide-y divide-border-subtle">
                  {[...findings].sort(bySeverity).map((finding) => (
                    <li key={finding.id}>
                      <Link
                        href={`/findings/${finding.id}`}
                        className="flex items-center gap-3 px-4 py-2.5 transition-colors duration-(--duration-fast) hover:bg-surface-raised-hover"
                      >
                        <SeverityBadge severity={finding.severity} size="sm" />
                        <span className="min-w-0 flex-1 truncate text-body-sm text-text-primary">
                          {finding.title}
                        </span>
                        <span className="shrink-0 font-mono text-caption text-text-tertiary">
                          {finding.asset ?? finding.source}
                        </span>
                        <ChevronRight
                          className="size-3.5 shrink-0 text-text-tertiary"
                          aria-hidden
                        />
                      </Link>
                    </li>
                  ))}
                </ul>
              </Card>
            </>
          ) : null}
        </div>
      </div>
    </>
  )
}

/**
 * What discovery mapped.
 *
 * The pre-redesign page reduced the whole report to two counts and a joined string. The report
 * carries interfaces, subnets, live hosts, web hosts, services and the scanner's own notes —
 * all of which are the answer to "did discovery actually see my network", so all of it is shown.
 */
function DiscoveryPanel({ report }: { report: DiscoveryReport }) {
  return (
    <Card>
      <CardHeader
        title="Discovery"
        description="Run from this device, before the agents started."
        actions={
          <span className="text-caption text-text-tertiary" data-numeric>
            {report.duration_seconds.toFixed(1)}s
          </span>
        }
      />
      <CardBody className="space-y-5">
        <KeyValueList
          columns={3}
          items={[
            {
              label: 'Interfaces',
              value: String(report.interfaces.length),
              icon: <Network className="size-3.5" />,
            },
            {
              label: 'Subnets',
              value: report.subnets.length > 0 ? report.subnets.join(', ') : 'none',
              icon: <Waypoints className="size-3.5" />,
              mono: true,
            },
            {
              label: 'Live hosts',
              value: String(report.live_hosts.length),
              icon: <Server className="size-3.5" />,
            },
          ]}
        />

        {report.web_hosts.length > 0 ? (
          <div>
            <Eyebrow>
              <span className="inline-flex items-center gap-1.5">
                <Globe className="size-3.5" aria-hidden />
                Web services
              </span>
            </Eyebrow>
            <ul className="mt-1.5 space-y-1.5">
              {report.web_hosts.map((host) => (
                <li
                  key={host.host}
                  className="rounded-md border border-border-subtle bg-surface-sunken px-3 py-2"
                >
                  <p className="font-mono text-body-sm text-text-primary">{host.host}</p>
                  {host.urls.length > 0 ? (
                    <p className="mt-0.5 break-all font-mono text-caption text-text-tertiary">
                      {host.urls.join('  ·  ')}
                    </p>
                  ) : null}
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="text-body-sm text-text-tertiary">
            No web service answered. The agents still scan the target you gave directly.
          </p>
        )}

        {report.services.length > 0 ? (
          <div>
            <Eyebrow>Open services</Eyebrow>
            <div className="mt-1.5 overflow-x-auto">
              <table className="w-full text-body-sm">
                <thead>
                  <tr className="border-b border-border-subtle text-caption uppercase tracking-wide text-text-tertiary">
                    <th scope="col" className="py-1.5 pr-3 text-left font-medium">
                      Host
                    </th>
                    <th scope="col" className="py-1.5 pr-3 text-left font-medium">
                      Port
                    </th>
                    <th scope="col" className="py-1.5 pr-3 text-left font-medium">
                      Service
                    </th>
                    <th scope="col" className="py-1.5 text-left font-medium">
                      Product
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {report.services.map((service) => (
                    <tr key={`${service.host}:${service.port}/${service.protocol}`}>
                      <td className="py-1.5 pr-3 font-mono text-caption text-text-secondary">
                        {service.host}
                      </td>
                      <td className="py-1.5 pr-3 font-mono text-caption text-text-secondary">
                        {service.port}/{service.protocol}
                      </td>
                      {/* Untrusted: both come from a service banner. Text only. */}
                      <td className="py-1.5 pr-3 text-caption text-text-secondary">
                        {service.service ?? '—'}
                      </td>
                      <td className="py-1.5 text-caption text-text-secondary">
                        {[service.product, service.version].filter(Boolean).join(' ') || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}

        {report.notes.length > 0 ? (
          <div>
            <Eyebrow>Notes from the scan</Eyebrow>
            <ul className="mt-1.5 space-y-1">
              {report.notes.map((note, index) => (
                <li key={index} className="text-caption text-text-tertiary">
                  {note}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </CardBody>
    </Card>
  )
}
