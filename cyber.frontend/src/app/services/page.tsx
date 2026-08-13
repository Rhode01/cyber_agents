'use client'

import { createColumnHelper } from '@tanstack/react-table'
import Link from 'next/link'
import { useEffect, useMemo, useState } from 'react'

import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { DataTable } from '@/components/ui/DataTable'
import { Field, Input } from '@/components/ui/Field'
import {
  ArrowRight,
  Boxes,
  ChevronRight,
  Layers,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
} from '@/components/ui/icons'
import { Hint } from '@/components/ui/overlays'
import { Eyebrow, PageHeader } from '@/components/ui/PageHeader'
import { StatCard, StatGrid } from '@/components/ui/StatCard'
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/states'
import { useFindings, useRunDiscovery } from '@/lib/queries'
import { SEVERITY_WEIGHT } from '@/lib/severity'
import { cn } from '@/lib/utils'
import type { DiscoveryReport, Finding, ServicePort } from '@/types'

/**
 * The service inventory for this device.
 *
 * Discovery is a POST that actually runs nmap, so it is a mutation, not a query — it does not
 * belong behind a cache that might refetch it on window focus. The page therefore runs it once
 * on mount and otherwise only when asked, which is the same behaviour as before, made explicit.
 *
 * Every service is joined to its worst matching finding, so this answers "what is exposed, and
 * do we already know it is a problem" in one table rather than sending an analyst to `/findings`
 * to cross-reference by hand.
 *
 * `product`, `version`, `service` and `extra_info` all come from a service banner — a remote
 * host chose those strings. All rendered as text.
 */

/**
 * True when a finding's asset refers to this exact host, and (when the finding names a port)
 * that port.
 *
 * Host-level findings (asset without a port) apply to every service on the host; port-specific
 * findings only to that port. "localhost" and "127.0.0.1" are the same machine.
 *
 * Carried over unchanged from the pre-redesign page, including the reason for the port check
 * below — it is the difference between a correct join and showing an SSH finding beside MySQL.
 */
function findingMatchesService(finding: Finding, host: string, port: number): boolean {
  const asset = (finding.asset ?? '').toLowerCase().replace(/^https?:\/\//, '')
  if (!asset) return false
  const authority = asset.split('/')[0]
  if (!authority) return false
  const assetHost = authority.split(':')[0]
  const assetPort = authority.split(':')[1]
  if (!assetHost) return false

  const h = host.toLowerCase()
  const hostMatches =
    h === assetHost ||
    assetHost.startsWith(h) ||
    (h === '127.0.0.1' && (assetHost === 'localhost' || assetHost.startsWith('localhost.'))) ||
    (assetHost === 'localhost' && h.startsWith('127.'))
  if (!hostMatches) return false

  // The finding's own port is authoritative when it has one. The vulnerability agent sets
  // `port` and leaves `asset` as a bare host, so falling straight through to `return true`
  // would match every finding on a host against every service on it.
  if (finding.port !== null && finding.port !== undefined) return finding.port === port
  if (assetPort) return String(port) === assetPort
  return true
}

interface ServiceRow {
  service: ServicePort
  /** The worst finding that matches this exact service, or null when none does. */
  finding: Finding | null
  /** Every matching finding, for the count beside the worst one. */
  matches: number
}

const columnHelper = createColumnHelper<ServiceRow>()

export default function ServicesPage() {
  const discover = useRunDiscovery()
  const findingsQuery = useFindings({ limit: 200 })
  const [report, setReport] = useState<DiscoveryReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')

  /* Discovery runs once on mount. `mutateAsync` inside an async IIFE rather than a bare call,
     so nothing sets state synchronously in the effect body — that cascades renders, and the
     lint rule for it has already caught this page once. */
  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const result = await discover.mutateAsync()
        if (!cancelled) setReport(result)
      } catch (cause) {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : 'Discovery failed.')
        }
      }
    })()
    return () => {
      cancelled = true
    }
    // `discover` is a stable mutation object from react-query; including it would re-run nmap
    // on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function rescan() {
    setError(null)
    try {
      const result = await discover.mutateAsync()
      setReport(result)
      void findingsQuery.refetch()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Discovery failed.')
    }
  }

  const findings = useMemo(() => findingsQuery.data?.items ?? [], [findingsQuery.data])

  const rows = useMemo<ServiceRow[]>(() => {
    const services = [...(report?.services ?? [])].sort(
      (a, b) => a.host.localeCompare(b.host) || a.port - b.port,
    )
    return services.map((service) => {
      const matches = findings
        .filter((finding) => findingMatchesService(finding, service.host, service.port))
        .sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity])
      return { service, finding: matches[0] ?? null, matches: matches.length }
    })
  }, [report, findings])

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase()
    if (!needle) return rows
    return rows.filter(({ service }) =>
      [
        service.host,
        String(service.port),
        service.protocol,
        service.service ?? '',
        service.product ?? '',
        service.version ?? '',
      ]
        .join(' ')
        .toLowerCase()
        .includes(needle),
    )
  }, [rows, search])

  const stats = useMemo(() => {
    const hosts = new Set(rows.map((row) => row.service.host))
    const products = new Set(
      rows
        .map((row) => row.service.product ?? row.service.service)
        .filter((value): value is string => Boolean(value)),
    )
    return {
      hosts: hosts.size,
      services: rows.length,
      products: products.size,
      withFindings: rows.filter((row) => row.finding !== null).length,
    }
  }, [rows])

  const columns = useMemo(
    () => [
      columnHelper.accessor((row) => row.service.host, {
        id: 'host',
        header: 'Host',
        size: 150,
        cell: (info) => (
          <span className="block truncate font-mono text-caption text-text-primary">
            {info.getValue()}
          </span>
        ),
      }),
      columnHelper.accessor((row) => row.service.port, {
        id: 'port',
        header: 'Port',
        size: 100,
        cell: (info) => (
          <span className="font-mono text-caption" data-numeric>
            {info.getValue()}
            <span className="text-text-tertiary">/{info.row.original.service.protocol}</span>
          </span>
        ),
      }),
      columnHelper.accessor(
        (row) => row.service.product ?? row.service.service ?? 'unknown',
        {
          id: 'service',
          header: 'Service',
          cell: (info) => {
            const { service } = info.row.original
            const primary = service.product ?? service.service ?? 'Unknown'
            // `service` is skipped in the sub-line when it is already the headline, which it is
            // whenever the banner reported no product — otherwise the row reads "microsoft-ds"
            // twice and says nothing the second time.
            const detail = [
              service.product ? service.service : null,
              service.version,
              service.extra_info,
            ]
              .filter(Boolean)
              .join(' · ')
            return (
              <div className="min-w-0">
                {/* Untrusted: a remote host chose this banner text. */}
                <p className="truncate font-medium text-text-primary">{primary}</p>
                <p className="mt-0.5 truncate text-caption text-text-tertiary">
                  {detail || 'no version reported'}
                </p>
              </div>
            )
          },
        },
      ),
      columnHelper.accessor((row) => row.finding?.severity ?? 'none', {
        id: 'risk',
        header: 'Risk',
        size: 130,
        sortingFn: (a, b) => {
          const left = a.original.finding ? SEVERITY_WEIGHT[a.original.finding.severity] : -1
          const right = b.original.finding ? SEVERITY_WEIGHT[b.original.finding.severity] : -1
          return left - right
        },
        cell: (info) => {
          const { finding, matches } = info.row.original
          if (!finding) {
            return <span className="text-caption text-text-tertiary">Not assessed</span>
          }
          return (
            <span className="inline-flex items-center gap-1.5">
              <SeverityBadge severity={finding.severity} size="sm" />
              {matches > 1 ? (
                <Hint content={`${matches} findings match this service`}>
                  <span className="text-caption text-text-tertiary" data-numeric>
                    +{matches - 1}
                  </span>
                </Hint>
              ) : null}
            </span>
          )
        },
      }),
      columnHelper.display({
        id: 'finding',
        header: 'Finding',
        size: 260,
        cell: (info) => {
          const { finding } = info.row.original
          if (!finding) {
            return (
              <span className="text-caption text-text-tertiary">
                Run the pipeline against this host
              </span>
            )
          }
          return (
            <Link
              href={`/findings/${finding.id}`}
              className="flex items-center gap-1.5 text-body-sm text-text-secondary transition-colors hover:text-accent"
            >
              <span className="min-w-0 truncate">{finding.title}</span>
              <ChevronRight className="size-3.5 shrink-0" aria-hidden />
            </Link>
          )
        },
      }),
    ],
    [],
  )

  const scanning = discover.isPending

  return (
    <>
      <PageHeader
        title="Service inventory"
        description="Open ports on this device, from nmap -sV against its own interfaces, each joined to the worst finding that already covers it."
        meta={
          report ? (
            <Badge tone="neutral">
              {/* No newline between the number and the unit: JSX collapses the indentation to
                  a space, which renders as "13.6 s scan". */}
              <span data-numeric>{`${report.duration_seconds.toFixed(1)}s scan`}</span>
            </Badge>
          ) : null
        }
        actions={
          <Button
            variant="secondary"
            leadingIcon={<RefreshCw className="size-4" />}
            loading={scanning}
            onClick={() => void rescan()}
          >
            {scanning ? 'Scanning…' : 'Re-scan'}
          </Button>
        }
      />

      {error ? (
        <Card>
          <ErrorState
            title="Discovery failed"
            error={error}
            icon={<ShieldAlert className="size-5" />}
            onRetry={() => void rescan()}
          />
        </Card>
      ) : report === null ? (
        <Card>
          <LoadingState message="Scanning this device's services — nmap takes a few seconds" />
        </Card>
      ) : (
        <>
          <StatGrid>
            <StatCard
              label="Hosts"
              value={stats.hosts}
              hint="device addresses with services"
              icon={<Server className="size-4" />}
            />
            <StatCard
              label="Open services"
              value={stats.services}
              hint="ports answering"
              icon={<Layers className="size-4" />}
            />
            <StatCard
              label="Distinct products"
              value={stats.products}
              hint="service banners seen"
              icon={<Boxes className="size-4" />}
            />
            <StatCard
              label="Already assessed"
              value={stats.withFindings}
              tone={stats.withFindings > 0 ? 'accent' : 'default'}
              hint={
                stats.services > 0
                  ? `${stats.services - stats.withFindings} not yet covered by a finding`
                  : 'nothing to assess'
              }
              icon={<ShieldAlert className="size-4" />}
            />
          </StatGrid>

          <div className="mt-4">
            <DataTable
              label="Open services on this device"
              data={filtered}
              columns={columns as never}
              getRowId={(row) => `${row.service.host}:${row.service.port}/${row.service.protocol}`}
              error={findingsQuery.error}
              onRetry={() => void findingsQuery.refetch()}
              initialSorting={[{ id: 'risk', desc: true }]}
              pageSize={50}
              toolbar={
                <div className="w-full sm:max-w-64">
                  <Field label="Search services" labelHidden>
                    <Input
                      type="search"
                      placeholder="Host, port, product…"
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                      leading={<Search className="size-4" />}
                    />
                  </Field>
                </div>
              }
              empty={
                <EmptyState
                  icon={<Server className="size-5" />}
                  title={
                    rows.length === 0
                      ? 'No services detected'
                      : 'Nothing matches this search'
                  }
                  description={
                    rows.length === 0
                      ? 'Nothing answered on this device’s own addresses. That is a normal result on a locked-down host — Re-scan to try again.'
                      : 'Clear the search to see every open port.'
                  }
                  action={
                    rows.length === 0 ? (
                      <Button variant="secondary" onClick={() => void rescan()}>
                        Re-scan
                      </Button>
                    ) : null
                  }
                />
              }
            />
          </div>

          {stats.services > stats.withFindings ? (
            <Card className="mt-4">
              <CardBody className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-body-sm text-text-secondary">
                  <span className="font-medium text-text-primary" data-numeric>
                    {stats.services - stats.withFindings}
                  </span>{' '}
                  open service{stats.services - stats.withFindings === 1 ? '' : 's'} have never
                  been assessed. An unassessed port is an unknown, not a safe one.
                </p>
                <Button
                  size="sm"
                  variant="primary"
                  href="/run"
                  trailingIcon={<ArrowRight className="size-3.5" />}
                >
                  Run the pipeline
                </Button>
              </CardBody>
            </Card>
          ) : null}

          {(report.notes.length > 0 || report.subnets.length > 0) && (
            <Card className="mt-4">
              <CardHeader
                title="Scan context"
                description="What discovery looked at, and anything it wanted to tell you."
              />
              <CardBody className="space-y-4">
                {report.subnets.length > 0 ? (
                  <div>
                    <Eyebrow>Subnets probed</Eyebrow>
                    <p className="mt-1 font-mono text-caption text-text-secondary">
                      {report.subnets.join('  ·  ')}
                    </p>
                  </div>
                ) : null}
                {report.interfaces.length > 0 ? (
                  <div>
                    <Eyebrow>Interfaces</Eyebrow>
                    <ul className="mt-1 space-y-0.5">
                      {report.interfaces.map((iface) => (
                        <li
                          key={`${iface.name}-${iface.ip}`}
                          className="font-mono text-caption text-text-secondary"
                        >
                          <span className="text-text-primary">{iface.name}</span> {iface.ip}/
                          {iface.prefix}
                          <span className="text-text-tertiary"> — {iface.subnet}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                {report.notes.length > 0 ? (
                  <div>
                    <Eyebrow>Notes</Eyebrow>
                    <ul className={cn('mt-1 space-y-0.5')}>
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
          )}
        </>
      )}
    </>
  )
}
