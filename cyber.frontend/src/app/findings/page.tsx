'use client'

import { createColumnHelper } from '@tanstack/react-table'
import { useQueryState } from 'nuqs'
import { Suspense, useMemo, useState } from 'react'

import { FindingDrawer } from '@/components/findings/FindingDrawer'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { DataTable } from '@/components/ui/DataTable'
import { Field, Input, NativeSelect } from '@/components/ui/Field'
import { FileSearch, Search, SlidersHorizontal } from '@/components/ui/icons'
import { Hint } from '@/components/ui/overlays'
import { PageHeader } from '@/components/ui/PageHeader'
import { EmptyState, TableSkeleton } from '@/components/ui/states'
import { AGENT_ICON } from '@/components/ui/icons'
import { useFindings } from '@/lib/queries'
import {
  FINDING_TYPE_LABEL,
  FINDING_TYPE_ORDER,
  OPEN_STATUSES,
  STATUS_LABEL,
  formatLocation,
} from '@/lib/findings'
import { SEVERITY_LABEL, SEVERITY_ORDER, SEVERITY_WEIGHT } from '@/lib/severity'
import { cn } from '@/lib/utils'
import { AGENT_KINDS, type Finding } from '@/types'

/**
 * The findings queue.
 *
 * Filter state lives in the URL through `nuqs`, so a filtered view is a shareable link — the
 * thing an analyst most often wants to send a colleague, and the thing the previous
 * component-state version made impossible.
 *
 * Filtering is client-side over one fetched page. That is a deliberate limit and it is
 * bounded: the query asks for 200 and the count is shown, so a larger dataset needs server
 * filtering rather than a bigger number here. Server-side faceting is the follow-up.
 */

const columnHelper = createColumnHelper<Finding>()

/**
 * Suspense boundary around the queue.
 *
 * `nuqs` reads the URL through `useSearchParams()`, which forces a client-side bailout during
 * prerendering. Without this boundary `next build` fails outright on this route — a bug the dev
 * server hides completely, because dev never prerenders. The fallback mirrors the real layout
 * so the handoff does not shift anything.
 */
export default function FindingsPage() {
  return (
    <Suspense fallback={<FindingsFallback />}>
      <FindingsQueue />
    </Suspense>
  )
}

function FindingsFallback() {
  return (
    <>
      <PageHeader
        title="Findings"
        description="Every detection this platform has produced, newest observation first."
      />
      <div className="overflow-hidden rounded-lg border border-border-default bg-surface-raised">
        <TableSkeleton rows={8} columns={6} />
      </div>
    </>
  )
}

function FindingsQueue() {
  const [search, setSearch] = useQueryState('q', { defaultValue: '', clearOnDefault: true })
  const [severity, setSeverity] = useQueryState('severity', {
    defaultValue: '',
    clearOnDefault: true,
  })
  const [agent, setAgent] = useQueryState('agent', { defaultValue: '', clearOnDefault: true })
  const [kind, setKind] = useQueryState('type', { defaultValue: '', clearOnDefault: true })
  const [status, setStatus] = useQueryState('status', {
    defaultValue: 'open',
    clearOnDefault: true,
  })

  /* Two pieces of state, not one, and the reason is keyboard focus.
     Collapsing these into `selected: Finding | null` and closing by setting it to null
     unmounts Radix's `Dialog.Root` in the same tick as the close — so its focus-restore never
     runs and a keyboard user who presses Escape is dumped back at the top of the document.
     Keeping the finding while `open` goes false lets Radix complete the close and hand focus
     back to the row that opened it. */
  const [selected, setSelected] = useState<Finding | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)

  const query = useFindings({ limit: 200 })
  // Memoised: `?? []` is a new array each render, which would invalidate the filter memo below.
  const all = useMemo(() => query.data?.items ?? [], [query.data])

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return all.filter((finding) => {
      if (severity && finding.severity !== severity) return false
      if (agent && finding.agent !== agent) return false
      if (kind && finding.finding_type !== kind) return false
      if (status === 'open' && !OPEN_STATUSES.includes(finding.status)) return false
      if (status && status !== 'open' && status !== 'all' && finding.status !== status) {
        return false
      }
      if (!needle) return true
      // Searched fields are the ones an analyst actually types: what it is, where it is.
      return (
        finding.title.toLowerCase().includes(needle) ||
        (finding.asset ?? '').toLowerCase().includes(needle) ||
        (finding.service ?? '').toLowerCase().includes(needle) ||
        finding.cve_ids.some((cve) => cve.toLowerCase().includes(needle))
      )
    })
  }, [all, search, severity, agent, kind, status])

  const columns = useMemo(
    () => [
      columnHelper.accessor('severity', {
        header: 'Severity',
        size: 130,
        sortingFn: (a, b) =>
          SEVERITY_WEIGHT[a.original.severity] - SEVERITY_WEIGHT[b.original.severity],
        cell: (info) => <SeverityBadge severity={info.getValue()} size="sm" />,
      }),
      columnHelper.accessor('title', {
        header: 'Finding',
        cell: (info) => (
          <div className="min-w-0">
            <p className="truncate font-medium text-text-primary">{info.getValue()}</p>
            <p className="mt-0.5 truncate text-caption text-text-tertiary">
              {FINDING_TYPE_LABEL[info.row.original.finding_type]}
            </p>
          </div>
        ),
      }),
      columnHelper.accessor((row) => formatLocation(row), {
        id: 'location',
        header: 'Location',
        size: 200,
        cell: (info) => (
          // `block`, not the default inline span: `text-overflow: ellipsis` has nothing to
          // clip on an inline box, so a long URL bleeds over the next column instead.
          <span className="block truncate font-mono text-caption" title={info.getValue()}>
            {info.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor('agent', {
        header: 'Agent',
        size: 130,
        cell: (info) => {
          const Icon = AGENT_ICON[info.getValue()]
          return (
            <span className="inline-flex items-center gap-1.5 capitalize">
              <Icon className="size-3.5 shrink-0 text-text-tertiary" aria-hidden />
              {info.getValue()}
            </span>
          )
        },
      }),
      columnHelper.accessor('status', {
        header: 'Status',
        size: 110,
        cell: (info) => <Badge tone="neutral" size="sm">{STATUS_LABEL[info.getValue()]}</Badge>,
      }),
      columnHelper.accessor('detected_at', {
        header: 'Detected',
        size: 130,
        cell: (info) => (
          <Hint content={new Date(info.getValue()).toLocaleString()}>
            <span className="text-caption text-text-tertiary">{relativeTime(info.getValue())}</span>
          </Hint>
        ),
      }),
    ],
    [],
  )

  const activeFilters = [severity, agent, kind, search.trim()].filter(Boolean).length
  const narrowed = status !== 'all'

  return (
    <>
      <PageHeader
        title="Findings"
        description="Every detection this platform has produced, newest observation first."
        meta={
          query.data ? (
            <Badge tone="neutral">
              <span data-numeric>{filtered.length}</span>
              {filtered.length !== all.length ? (
                <span className="text-text-tertiary">
                  {' '}
                  of <span data-numeric>{all.length}</span>
                </span>
              ) : null}
            </Badge>
          ) : null
        }
        actions={
          activeFilters > 0 || narrowed ? (
            <Button
              variant="ghost"
              leadingIcon={<SlidersHorizontal className="size-4" />}
              onClick={() => {
                void setSearch('')
                void setSeverity('')
                void setAgent('')
                void setKind('')
                void setStatus('all')
              }}
            >
              Clear filters
            </Button>
          ) : null
        }
      />

      <DataTable
        label="Findings"
        data={filtered}
        columns={columns as never}
        getRowId={(row) => row.id}
        isLoading={query.isPending}
        error={query.error}
        onRetry={() => void query.refetch()}
        onRowClick={(row) => {
          setSelected(row)
          setDrawerOpen(true)
        }}
        initialSorting={[{ id: 'severity', desc: true }]}
        toolbar={
          <>
            <div className="w-full sm:max-w-64">
              <Field label="Search findings" labelHidden>
                <Input
                  type="search"
                  placeholder="Title, host, service, CVE…"
                  value={search}
                  onChange={(event) => void setSearch(event.target.value)}
                  leading={<Search className="size-4" />}
                />
              </Field>
            </div>

            <FilterSelect
              label="Severity"
              value={severity}
              onChange={setSeverity}
              options={SEVERITY_ORDER.map((value) => ({
                value,
                label: SEVERITY_LABEL[value],
              }))}
            />
            <FilterSelect
              label="Agent"
              value={agent}
              onChange={setAgent}
              options={AGENT_KINDS.map((value) => ({ value, label: value }))}
            />
            <FilterSelect
              label="Kind"
              value={kind}
              onChange={setKind}
              options={FINDING_TYPE_ORDER.map((value) => ({
                value,
                label: FINDING_TYPE_LABEL[value],
              }))}
            />
            <FilterSelect
              label="Status"
              value={status}
              onChange={setStatus}
              allLabel="All statuses"
              options={[
                { value: 'open', label: 'Open only' },
                { value: 'resolved', label: STATUS_LABEL.resolved },
                { value: 'false_positive', label: STATUS_LABEL.false_positive },
              ]}
            />
          </>
        }
        empty={
          <EmptyState
            icon={<FileSearch className="size-5" />}
            title={all.length === 0 ? 'No findings yet' : 'Nothing matches these filters'}
            description={
              all.length === 0
                ? 'Submit a scanner report or a suspect message and the agents will populate this queue.'
                : 'Every finding was excluded by the current filters. Clearing them will show the full queue.'
            }
            action={
              all.length === 0 ? (
                <Button href="/scans" variant="primary">
                  Upload a scan
                </Button>
              ) : (
                <Button
                  variant="secondary"
                  onClick={() => {
                    void setSearch('')
                    void setSeverity('')
                    void setAgent('')
                    void setKind('')
                    void setStatus('all')
                  }}
                >
                  Clear filters
                </Button>
              )
            }
          />
        }
      />

      <FindingDrawer
        finding={selected}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      />
    </>
  )
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
  allLabel,
}: {
  label: string
  value: string
  onChange: (next: string) => void
  options: readonly { value: string; label: string }[]
  allLabel?: string
}) {
  return (
    <div className={cn('w-full sm:w-auto')}>
      <Field label={label} labelHidden>
        <NativeSelect
          value={value}
          onChange={(event) => void onChange(event.target.value)}
          aria-label={label}
          className="sm:w-auto sm:min-w-36"
        >
          <option value="">{allLabel ?? `All ${label.toLowerCase()}`}</option>
          {options.map((option) => (
            <option key={option.value} value={option.value} className="capitalize">
              {option.label}
            </option>
          ))}
        </NativeSelect>
      </Field>
    </div>
  )
}

/** Compact age, with the exact timestamp available on hover. */
function relativeTime(iso: string): string {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return '—'
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000))
  if (seconds < 60) return 'just now'
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.round(hours / 24)
  if (days < 30) return `${days}d ago`
  return new Date(iso).toLocaleDateString()
}
