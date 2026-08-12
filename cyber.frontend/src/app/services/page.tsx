'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'

import { fetchFindings, runDiscovery } from '@/lib/api'
import { SEVERITY_LABEL, SEVERITY_ORDER } from '@/lib/severity'
import type { DiscoveryReport, Finding, ServicePort } from '@/types'

/** True when a finding's asset refers to this exact host, and (when the
 * finding names a port) that port. Host-level findings (asset without a port)
 * apply to every service on the host; port-specific findings only to that port.
 * "localhost" and "127.0.0.1" are the same machine. */
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

  // The finding's own port is authoritative when it has one. The vulnerability
  // agent sets `port` and leaves `asset` as a bare host, so falling straight
  // through to `return true` would match every finding on a host against every
  // service on it - showing an SSH finding beside a MySQL service.
  if (finding.port !== null && finding.port !== undefined) return finding.port === port
  if (assetPort) return String(port) === assetPort
  return true
}

/** The rows for one service, matching the nmap result card layout. */
interface ServiceRow {
  service: ServicePort
  finding: Finding | null
}

function DetailTable({ rows }: { rows: Array<[string, string]> }) {
  return (
    <table
      style={{
        width: '100%',
        borderCollapse: 'collapse',
        fontSize: '0.82rem',
      }}
    >
      <tbody>
        {rows.map(([category, details]) => (
          <tr key={category} style={{ borderBottom: '1px solid var(--border)' }}>
            <th
              style={{
                textAlign: 'left',
                width: '25%',
                padding: '0.55rem 0.9rem',
                fontWeight: 700,
                color: 'var(--faint)',
                textTransform: 'uppercase',
                fontSize: '0.72rem',
                letterSpacing: '0.06em',
                background: 'rgba(255,255,255,0.02)',
                borderRight: '1px solid var(--border)',
                verticalAlign: 'top',
              }}
            >
              {category}
            </th>
            <td
              style={{
                padding: '0.55rem 0.9rem',
                color: 'var(--text)',
                whiteSpace: 'pre-wrap',
              }}
            >
              {details || '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function riskText(finding: Finding): string {
  const label = SEVERITY_LABEL[finding.severity] ?? SEVERITY_LABEL.info
  const confidence = Math.round(finding.confidence * 100)
  return `${label} severity · ${confidence}% confidence${finding.description ? ` — ${finding.description}` : ''}`
}

export default function ServicesPage() {
  const [report, setReport] = useState<DiscoveryReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [findings, setFindings] = useState<Finding[]>([])
  const [scanning, setScanning] = useState(false)

  const loadFindings = async () => {
    const all: Finding[] = []
    for (let offset = 0; ; offset += 200) {
      const page = await fetchFindings(200, offset)
      all.push(...page.items)
      if (offset + page.items.length >= page.total) break
    }
    setFindings(all)
  }

  /** Discovery and findings together. `loadFindings` sets its own state, so only
   *  the report comes back. */
  const load = async (): Promise<void> => {
    const [discovered] = await Promise.all([runDiscovery(), loadFindings()])
    setReport(discovered)
  }

  useEffect(() => {
    // Every state write happens after an await, so nothing is set synchronously in
    // the effect body - that cascades renders, and `loading` already starts true.
    // `cancelled` stops a slow discovery writing into an unmounted page.
    let cancelled = false

    void (async () => {
      try {
        await load()
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Discovery failed')
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()

    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /** The Re-scan button. An event handler, so showing the spinner up front here is
   *  a direct response to a click rather than a cascading render. */
  const rescanned = async () => {
    setScanning(true)
    setError(null)
    try {
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Discovery failed')
    } finally {
      setScanning(false)
    }
  }

  const rows = useMemo<ServiceRow[]>(() => {
    const services = [...(report?.services ?? [])].sort(
      (a, b) => a.host.localeCompare(b.host) || a.port - b.port,
    )

    return services.map((service) => {
      const candidates = findings
        .filter((f) => findingMatchesService(f, service.host, service.port))
        .sort(
          (a, b) =>
            (SEVERITY_ORDER.indexOf(a.severity) ?? 4) -
            (SEVERITY_ORDER.indexOf(b.severity) ?? 4),
        )
      return { service, finding: candidates[0] ?? null }
    })
  }, [report, findings])

  const stats = useMemo(() => {
    const hosts = new Set(rows.map((r) => r.service.host))
    const products = new Set(
      rows.map((r) => r.service.product ?? r.service.service).filter(Boolean),
    )
    const findingsCount = rows.filter((r) => r.finding !== null).length
    return { hosts: hosts.size, services: rows.length, products: products.size, findingsCount }
  }, [rows])

  const grouped = useMemo(() => {
    const map = new Map<string, ServiceRow[]>()
    for (const row of rows) {
      if (!map.has(row.service.host)) map.set(row.service.host, [])
      map.get(row.service.host)!.push(row)
    }
    return [...map.entries()]
  }, [rows])

  return (
    <main>
      <div className="page-title">
        <div>
          <span className="eyebrow">Nmap scan results</span>
          <h1>Services Active</h1>
          <p className="subtitle">
            Services detected on this device by the discovery stage (nmap -sV against the
            device&apos;s own interfaces).
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.6rem' }}>
          <button
            type="button"
            className="btn"
            onClick={rescanned}
            disabled={scanning || loading}
          >
            {scanning ? 'Scanning…' : '↻ Re-scan'}
          </button>
          <Link href="/" className="btn btn-ghost">← Home</Link>
        </div>
      </div>

      {error && (
        <section className="panel" style={{ borderColor: 'rgba(251,113,133,0.3)' }}>
          <span className="status bad">● Discovery failed</span>
          <p className="error">{error}</p>
        </section>
      )}

      {loading && (
        <span className="status pending">Scanning the device&apos;s services…</span>
      )}

      {!loading && !error && report && (
        <>
          <div className="stat-grid" style={{ marginBottom: '1.5rem' }}>
            <div className="stat-card accent">
              <div className="label">Active Hosts</div>
              <div className="value">{stats.hosts}</div>
              <div className="sub">device addresses with services</div>
            </div>
            <div className="stat-card">
              <div className="label">Services</div>
              <div className="value">{stats.services}</div>
              <div className="sub">open ports detected</div>
            </div>
            <div className="stat-card">
              <div className="label">Products</div>
              <div className="value">{stats.products}</div>
              <div className="sub">distinct service banners</div>
            </div>
            <div className="stat-card ok">
              <div className="label">With Findings</div>
              <div className="value">{stats.findingsCount}</div>
              <div className="sub">services linked to a finding</div>
            </div>
          </div>

          {report.notes.length > 0 && (
            <p style={{ fontSize: '0.75rem', color: 'var(--faint)', marginBottom: '1rem' }}>
              {report.notes.join(' · ')}
            </p>
          )}

          {grouped.length === 0 ? (
            <section className="panel">
              <p style={{ color: 'var(--muted)', margin: 0 }}>
                No services were detected on the device&apos;s addresses. Try the Re-scan button.
              </p>
            </section>
          ) : (
            grouped.map(([host, hostRows]) => (
              <section key={host} className="panel" style={{ marginBottom: '1.25rem' }}>
                <div style={{ marginBottom: '0.75rem' }}>
                  <span className="eyebrow" style={{ marginRight: '0.5rem' }}>
                    Host
                  </span>
                  <span style={{ fontWeight: 700, fontSize: '1rem' }}>{host}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {hostRows.map(({ service, finding }) => (
                    <div
                      key={`${service.host}:${service.port}`}
                      style={{
                        border: '1px solid var(--border)',
                        borderRadius: '10px',
                        overflow: 'hidden',
                        background: 'var(--bg-elev)',
                      }}
                    >
                      <DetailTable
                        rows={[
                          ['Host', service.host],
                          ['Port', `${service.port}${service.protocol !== 'tcp' ? `/${service.protocol}` : ''}`],
                          ['Service', service.product ?? service.service ?? 'Unknown'],
                          ['Version', service.version ?? '—'],
                          ['Finding', finding?.title ?? `No findings recorded for ${host} yet.`],
                          ['Risk', finding ? riskText(finding) : 'Not assessed'],
                          [
                            'Recommendation',
                            finding?.recommendation ?? 'Run the agent pipeline against this host to assess the service.',
                          ],
                        ]}
                      />
                    </div>
                  ))}
                </div>
              </section>
            ))
          )}
        </>
      )}
    </main>
  )
}
