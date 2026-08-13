'use client'

import { createColumnHelper } from '@tanstack/react-table'
import Link from 'next/link'
import { useMemo, useState } from 'react'

import { IntakeProgress } from '@/components/intake/IntakeProgress'
import { Badge, SeverityBadge, SeverityTally } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { DataTable } from '@/components/ui/DataTable'
import { Field, Input } from '@/components/ui/Field'
import { FileDropzone, formatBytes } from '@/components/ui/FileDropzone'
import {
  AGENT_ICON,
  ChevronRight,
  FileSearch,
  Layers,
  ScanLine,
  Server,
  Upload,
} from '@/components/ui/icons'
import { KeyValueList } from '@/components/ui/KeyValueList'
import { Hint, TabPanel } from '@/components/ui/overlays'
import { PageHeader } from '@/components/ui/PageHeader'
import { EmptyState, InlineError } from '@/components/ui/states'
import { bySeverity, formatLocation } from '@/lib/findings'
import { intakeIsFinished, useFindings, useIntakeFindings, useScan, useScans, useUploadScan } from '@/lib/queries'
import { SEVERITY_ORDER, emptySeverityCounts } from '@/lib/severity'
import { cn } from '@/lib/utils'
import type { AgentKind, Finding, Scan, ScanIntakeStatus, Severity } from '@/types'

/**
 * Scans: the intake, and the history.
 *
 * Two things live here because they are two halves of one question — "what has been scanned?"
 *
 * **Intake** was previously unreachable. `POST /scans` has existed in the backend since Phase 2
 * and nothing in the browser ever called it, so the only way to get a scanner report into the
 * platform was curl. That is now a drop target.
 *
 * **Sessions** is the pre-redesign view, preserved: findings grouped by the run that produced
 * them, which answers a different question from the intake table (what did one *sweep* find,
 * across agents) and would have been lost if this page had simply been replaced.
 */

const SCAN_STATUS_TONE: Record<ScanIntakeStatus, 'neutral' | 'active' | 'ok' | 'error'> = {
  pending: 'neutral',
  parsing: 'active',
  analyzing: 'active',
  completed: 'ok',
  failed: 'error',
}

const SCAN_STATUS_LABEL: Record<ScanIntakeStatus, string> = {
  pending: 'Queued',
  parsing: 'Parsing',
  analyzing: 'Analysing',
  completed: 'Completed',
  failed: 'Failed',
}

const scanColumns = createColumnHelper<Scan>()

export default function ScansPage() {
  return (
    <>
      <PageHeader
        title="Scan intake"
        description="Upload an Nmap or OpenVAS report and the vulnerability agent turns it into findings. Everything already submitted is listed below."
      />

      <TabPanel
        tabs={[
          { value: 'upload', label: 'Upload a report', content: <UploadPanel /> },
          { value: 'history', label: 'Submitted scans', content: <ScanHistory /> },
          { value: 'sessions', label: 'Scan sessions', content: <SessionsPanel /> },
        ]}
      />
    </>
  )
}

/* --------------------------------------------------------------- upload */

/**
 * Drop a report, watch it move, read what it found.
 *
 * `asset` is optional and explained rather than left as a bare box: for an Nmap report the
 * hosts come from the file, so typing one only helps when the report has none of its own.
 */
function UploadPanel() {
  const [file, setFile] = useState<File | null>(null)
  const [asset, setAsset] = useState('')
  const [scanId, setScanId] = useState<string | null>(null)

  const upload = useUploadScan()
  const scan = useScan(scanId ?? undefined)
  const finished = intakeIsFinished(scan.data?.status)
  const findings = useIntakeFindings(scanId ? { scanId } : null, finished)

  const submitted = scan.data

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)] lg:items-start">
      <Card>
        <CardHeader
          title="New report"
          description="Nmap XML (-oX) or an OpenVAS/Greenbone XML export."
        />
        <CardBody className="space-y-4">
          <FileDropzone
            label="Scanner report"
            accept=".xml,text/xml,application/xml"
            hint="XML only. The server checks the format and rejects anything it cannot parse."
            selected={file}
            onSelect={setFile}
            onClear={() => setFile(null)}
            disabled={upload.isPending}
          />

          <Field
            label="Asset override"
            hint="Optional. Nmap reports carry their own hosts — set this only when the report has none."
          >
            <Input
              value={asset}
              onChange={(event) => setAsset(event.target.value)}
              placeholder="10.0.0.5"
              disabled={upload.isPending}
            />
          </Field>

          {upload.error ? <InlineError error={upload.error} /> : null}

          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="primary"
              leadingIcon={<Upload className="size-4" />}
              disabled={!file}
              loading={upload.isPending}
              onClick={() => {
                if (!file) return
                upload.mutate(
                  { file, asset: asset.trim() || undefined },
                  {
                    onSuccess: (created) => {
                      setScanId(created.id)
                      setFile(null)
                    },
                  },
                )
              }}
            >
              Analyse report
            </Button>
            {submitted ? (
              <Button
                variant="ghost"
                onClick={() => {
                  setScanId(null)
                  setAsset('')
                }}
              >
                Start over
              </Button>
            ) : null}
          </div>
        </CardBody>
      </Card>

      {submitted ? (
        <Card>
          <CardHeader
            title={submitted.filename}
            description={`${submitted.format === 'nmap_xml' ? 'Nmap XML' : 'OpenVAS XML'} · ${formatBytes(submitted.size_bytes)}`}
            actions={
              <Badge tone={SCAN_STATUS_TONE[submitted.status]}>
                {SCAN_STATUS_LABEL[submitted.status]}
              </Badge>
            }
          />
          <CardBody className="space-y-5">
            <IntakeProgress
              status={submitted.status}
              error={submitted.error}
              summary={[
                { label: 'hosts', value: submitted.host_count },
                { label: 'findings', value: submitted.finding_count },
              ]}
            />

            <KeyValueList
              items={[
                { label: 'Asset', value: submitted.asset ?? 'from the report', mono: true },
                { label: 'SHA-256', value: submitted.sha256.slice(0, 16) + '…', mono: true },
                {
                  label: 'Submitted',
                  value: new Date(submitted.created_at).toLocaleString(),
                },
                {
                  label: 'Finished',
                  value: submitted.completed_at
                    ? new Date(submitted.completed_at).toLocaleString()
                    : '—',
                },
              ]}
            />

            {finished && submitted.status === 'completed' ? (
              <div className="border-t border-border-subtle pt-4">
                {findings.isPending ? (
                  <p className="text-body-sm text-text-tertiary">Loading findings…</p>
                ) : findings.error ? (
                  <InlineError
                    error={findings.error}
                    onRetry={() => void findings.refetch()}
                  />
                ) : (findings.data?.items.length ?? 0) === 0 ? (
                  <p className="text-body-sm text-text-tertiary">
                    Parsed cleanly and no rule matched. That is a statement about the rules,
                    not a clean bill of health.
                  </p>
                ) : (
                  <ul className="space-y-1.5">
                    {[...(findings.data?.items ?? [])]
                      .sort(bySeverity)
                      .map((finding) => (
                        <li key={finding.id}>
                          <Link
                            href={`/findings/${finding.id}`}
                            className="flex items-center gap-2.5 rounded-md border border-border-subtle bg-surface-sunken px-3 py-2 transition-colors hover:border-border-strong"
                          >
                            <SeverityBadge severity={finding.severity} size="sm" />
                            <span className="min-w-0 flex-1 truncate text-body-sm text-text-primary">
                              {finding.title}
                            </span>
                            <span className="shrink-0 font-mono text-caption text-text-tertiary">
                              {formatLocation(finding)}
                            </span>
                            <ChevronRight
                              className="size-3.5 shrink-0 text-text-tertiary"
                              aria-hidden
                            />
                          </Link>
                        </li>
                      ))}
                  </ul>
                )}
              </div>
            ) : null}
          </CardBody>
        </Card>
      ) : (
        <Card>
          <CardBody>
            <EmptyState
              icon={<ScanLine className="size-5" />}
              title="Nothing submitted yet"
              description="Upload a report and its progress through parsing and analysis appears here, followed by whatever it found."
            />
          </CardBody>
        </Card>
      )}
    </div>
  )
}

/* -------------------------------------------------------------- history */

function ScanHistory() {
  const query = useScans(50)
  const scans = query.data?.items ?? []

  const columns = useMemo(
    () => [
      scanColumns.accessor('status', {
        header: 'Status',
        size: 120,
        cell: (info) => (
          <Badge tone={SCAN_STATUS_TONE[info.getValue()]} size="sm">
            {SCAN_STATUS_LABEL[info.getValue()]}
          </Badge>
        ),
      }),
      scanColumns.accessor('filename', {
        header: 'Report',
        cell: (info) => {
          const scan = info.row.original
          return (
            <div className="min-w-0">
              <p className="truncate font-medium text-text-primary">{info.getValue()}</p>
              {/* A failed scan's reason belongs on the row, not in a banner above the table.
                  Shown verbatim: "not well-formed XML: line 10, column 8" is actionable and a
                  generic "analysis failed" is not. */}
              {scan.status === 'failed' ? (
                <p className="mt-0.5 text-caption text-severity-critical">
                  {scan.error ?? 'No reason recorded.'}
                </p>
              ) : (
                <p className="mt-0.5 truncate text-caption text-text-tertiary">
                  {scan.format === 'nmap_xml' ? 'Nmap XML' : 'OpenVAS XML'} ·{' '}
                  {formatBytes(scan.size_bytes)}
                </p>
              )}
            </div>
          )
        },
      }),
      scanColumns.accessor((row) => row.asset ?? '', {
        id: 'asset',
        header: 'Asset',
        size: 150,
        cell: (info) => (
          <span className="block truncate font-mono text-caption">
            {info.getValue() || '—'}
          </span>
        ),
      }),
      scanColumns.accessor('host_count', {
        header: 'Hosts',
        size: 80,
        cell: (info) => (
          <span className="font-mono text-caption" data-numeric>
            {info.getValue()}
          </span>
        ),
      }),
      scanColumns.accessor('finding_count', {
        header: 'Findings',
        size: 90,
        cell: (info) => (
          <span className="font-mono text-caption" data-numeric>
            {info.getValue()}
          </span>
        ),
      }),
      scanColumns.accessor('created_at', {
        header: 'Submitted',
        size: 150,
        cell: (info) => (
          <span className="text-caption text-text-tertiary">
            {new Date(info.getValue()).toLocaleString()}
          </span>
        ),
      }),
    ],
    [],
  )

  const failed = scans.filter((scan) => scan.status === 'failed').length

  return (
    <div className="space-y-3">
      {failed > 0 ? (
        <p role="status" className="text-body-sm text-text-secondary">
          <span className="font-medium text-severity-critical">
            <span data-numeric>{failed}</span> of{' '}
            <span data-numeric>{scans.length}</span> scans failed
          </span>
          {' — each one’s reason is on its row below.'}
        </p>
      ) : null}

      <DataTable
        label="Submitted scans"
        data={scans}
        columns={columns as never}
        getRowId={(row) => row.id}
        isLoading={query.isPending}
        error={query.error}
        onRetry={() => void query.refetch()}
        initialSorting={[{ id: 'created_at', desc: true }]}
        empty={
          <EmptyState
            icon={<Upload className="size-5" />}
            title="No scans submitted"
            description="Nothing has been uploaded through the intake yet. Findings from browser-driven runs appear under Scan sessions instead."
          />
        }
      />
    </div>
  )
}

/* ------------------------------------------------------------- sessions */

interface ScanSession {
  id: string
  agents: AgentKind[]
  /** True when the findings were stamped with a run id, so this is one pipeline sweep. */
  isRun: boolean
  asset: string
  source: string
  timestamp: string
  findings: Finding[]
  severities: Record<Severity, number>
  status: 'clean' | 'warning' | 'critical'
}

/**
 * Findings grouped into the sweep that produced them.
 *
 * Findings stamped with a `run_id` form one session per run, keeping every agent's results for
 * that run together instead of merging into whatever else was scanned against the same target
 * that day. Untagged findings fall back to agent + asset + source + hour, so scans from
 * different times stay distinguishable.
 *
 * Carried over from the pre-redesign page unchanged in logic.
 */
function groupIntoSessions(findings: readonly Finding[]): ScanSession[] {
  const groups = new Map<string, Finding[]>()
  for (const finding of findings) {
    const key =
      finding.run_id ??
      `${finding.agent}::${finding.asset ?? 'unknown'}::${finding.source}::${finding.detected_at.slice(0, 13)}`
    const bucket = groups.get(key)
    if (bucket) bucket.push(finding)
    else groups.set(key, [finding])
  }

  return [...groups.entries()]
    .map(([key, items]): ScanSession => {
      const first = items[0]!
      const severities = emptySeverityCounts()
      for (const finding of items) severities[finding.severity] += 1

      const timestamp = items
        .map((finding) => finding.detected_at)
        .sort()
        .reverse()[0]!

      return {
        id: key,
        agents: [...new Set(items.map((finding) => finding.agent))],
        isRun: first.run_id != null,
        asset: first.asset ?? 'unknown',
        source: [...new Set(items.map((finding) => finding.source))].join(', '),
        timestamp,
        findings: items,
        severities,
        status:
          severities.critical > 0 ? 'critical' : severities.high > 0 ? 'warning' : 'clean',
      }
    })
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
}

const SESSION_TONE = { critical: 'error', warning: 'warn', clean: 'ok' } as const
const SESSION_LABEL = { critical: 'Critical', warning: 'Warning', clean: 'Clean' } as const

function SessionsPanel() {
  // 200 is the transport's page size. The count below discloses the cap rather than
  // presenting a truncated list as the whole history.
  const query = useFindings({ limit: 200 })
  const [expanded, setExpanded] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<'all' | 'critical' | 'warning' | 'clean'>(
    'all',
  )
  const [agentFilter, setAgentFilter] = useState<AgentKind | 'all'>('all')

  // Memoised: `?? []` allocates each render, which would defeat the grouping memo below.
  const all = useMemo(() => query.data?.items ?? [], [query.data])
  const sessions = useMemo(() => groupIntoSessions(all), [all])

  const filtered = sessions.filter((session) => {
    if (statusFilter !== 'all' && session.status !== statusFilter) return false
    if (agentFilter !== 'all' && !session.agents.includes(agentFilter)) return false
    return true
  })

  if (query.error) {
    return (
      <Card>
        <CardBody>
          <InlineError error={query.error} onRetry={() => void query.refetch()} />
        </CardBody>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader
        title="Scan sessions"
        description="Each pipeline run or agent invocation as one session, newest first."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <FilterPills
              value={statusFilter}
              onChange={setStatusFilter}
              options={[
                { value: 'all', label: 'All' },
                { value: 'critical', label: 'Critical' },
                { value: 'warning', label: 'Warning' },
                { value: 'clean', label: 'Clean' },
              ]}
            />
            <FilterPills
              value={agentFilter}
              onChange={setAgentFilter}
              options={[
                { value: 'all', label: 'Every agent' },
                { value: 'vulnerability', label: 'Vulnerability' },
                { value: 'phishing', label: 'Phishing' },
                { value: 'network', label: 'Network' },
                { value: 'webapp', label: 'Web app' },
              ]}
            />
          </div>
        }
      />

      {query.isPending ? (
        <CardBody>
          <p className="text-body-sm text-text-tertiary">Loading sessions…</p>
        </CardBody>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<FileSearch className="size-5" />}
          title={sessions.length === 0 ? 'No sessions yet' : 'Nothing matches these filters'}
          description={
            sessions.length === 0
              ? 'Run an agent or upload a report and the findings group into a session here.'
              : 'Every session was excluded. Clear the filters to see the full history.'
          }
          action={
            sessions.length === 0 ? (
              <Button href="/run" variant="secondary">
                Open the runner
              </Button>
            ) : null
          }
        />
      ) : (
        <ul className="divide-y divide-border-subtle">
          {filtered.map((session) => {
            const open = expanded === session.id
            return (
              <li key={session.id}>
                <button
                  type="button"
                  aria-expanded={open}
                  onClick={() => setExpanded(open ? null : session.id)}
                  className={cn(
                    'flex w-full flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3 text-left',
                    'transition-colors duration-(--duration-fast) hover:bg-surface-raised-hover',
                    open && 'bg-surface-raised-hover',
                  )}
                >
                  <ChevronRight
                    className={cn(
                      'size-4 shrink-0 text-text-tertiary transition-transform duration-(--duration-fast)',
                      open && 'rotate-90',
                    )}
                    aria-hidden
                  />
                  <Badge tone={SESSION_TONE[session.status]} size="sm" className="shrink-0">
                    {SESSION_LABEL[session.status]}
                  </Badge>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-body-sm text-text-primary">
                      {session.asset}
                    </span>
                    <span className="mt-0.5 flex flex-wrap items-center gap-x-2 text-caption text-text-tertiary">
                      <span className="inline-flex items-center gap-1">
                        {session.agents.map((agent) => {
                          const Icon = AGENT_ICON[agent]
                          return (
                            <Hint key={agent} content={agent}>
                              <Icon className="size-3" aria-label={agent} />
                            </Hint>
                          )
                        })}
                      </span>
                      <span>{session.isRun ? 'pipeline run' : session.source}</span>
                      <span aria-hidden>·</span>
                      <span>{new Date(session.timestamp).toLocaleString()}</span>
                    </span>
                  </span>
                  <SeverityTally counts={session.severities} order={SEVERITY_ORDER} />
                </button>

                {open ? (
                  <div className="border-t border-border-subtle bg-surface-sunken px-4 py-3">
                    <p className="mb-2 text-caption font-medium uppercase tracking-wide text-text-tertiary">
                      <span data-numeric>{session.findings.length}</span> finding
                      {session.findings.length === 1 ? '' : 's'} in this session
                    </p>
                    <ul className="space-y-1.5">
                      {[...session.findings].sort(bySeverity).map((finding) => (
                        <li key={finding.id}>
                          <Link
                            href={`/findings/${finding.id}`}
                            className="flex items-center gap-2.5 rounded-md border border-border-subtle bg-surface-raised px-3 py-2 transition-colors hover:border-border-strong"
                          >
                            <SeverityBadge severity={finding.severity} size="sm" />
                            <span className="min-w-0 flex-1 truncate text-body-sm text-text-primary">
                              {finding.title}
                            </span>
                            <ChevronRight
                              className="size-3.5 shrink-0 text-text-tertiary"
                              aria-hidden
                            />
                          </Link>
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </li>
            )
          })}
        </ul>
      )}

      {!query.isPending && sessions.length > 0 ? (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border-subtle px-4 py-2.5 text-caption text-text-tertiary">
          <span className="inline-flex items-center gap-1.5">
            <Layers className="size-3.5" aria-hidden />
            <span data-numeric>{filtered.length}</span> of{' '}
            <span data-numeric>{sessions.length}</span> sessions
          </span>
          <span className="inline-flex items-center gap-1.5">
            <Server className="size-3.5" aria-hidden />
            grouped from the newest <span data-numeric>{all.length}</span> of{' '}
            <span data-numeric>{query.data?.total ?? all.length}</span> findings
          </span>
        </div>
      ) : null}
    </Card>
  )
}

/**
 * A small segmented control.
 *
 * A row of buttons rather than a select, because there are four options and they are the
 * primary way this list is narrowed — hiding them behind a dropdown costs a click on the
 * action people take most.
 */
function FilterPills<T extends string>({
  value,
  onChange,
  options,
}: {
  value: T
  onChange: (next: T) => void
  options: readonly { value: T; label: string }[]
}) {
  return (
    <div
      role="group"
      className="inline-flex overflow-hidden rounded-md border border-border-default"
    >
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
          className={cn(
            'px-2.5 py-1 text-caption font-medium transition-colors duration-(--duration-fast)',
            'border-r border-border-default last:border-r-0',
            value === option.value
              ? 'bg-accent-surface text-accent'
              : 'text-text-tertiary hover:bg-surface-raised-hover hover:text-text-secondary',
          )}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}
