'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'

import { fetchRunStatus } from '@/lib/api'

const NAV = [
  { href: '/', label: 'Home' },
  { href: '/run', label: 'Run Agent' },
  { href: '/scans', label: 'Scans' },
  { href: '/phishing', label: 'Phishing' },
  { href: '/services', label: 'Services' },
  { href: '/findings', label: 'Findings' },
  { href: '/reports', label: 'Reports' },
]

type ScanState =
  | { kind: 'loading' }
  | { kind: 'running'; target: string }
  | { kind: 'idle' }
  | { kind: 'offline' }

function runTargetLabel(target: string): string {
  if (target.startsWith('email:')) return target.slice('email:'.length)
  if (target === 'quick') return 'quick auto-scan'
  return target
}

export default function Sidebar() {
  const pathname = usePathname()
  const [scan, setScan] = useState<ScanState>({ kind: 'loading' })

  useEffect(() => {
    let cancelled = false

    const poll = async () => {
      try {
        const status = await fetchRunStatus()
        if (cancelled) return
        if (status.scanning && status.current) {
          setScan({ kind: 'running', target: status.current.target })
        } else {
          setScan({ kind: 'idle' })
        }
      } catch {
        if (!cancelled) setScan({ kind: 'offline' })
      }
    }

    poll()
    const timer = setInterval(poll, 4000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [])

  let footerDot = 'dot ok'
  let footerText = 'Scan idle'
  if (scan.kind === 'loading') {
    footerDot = 'dot'
    footerText = 'Checking…'
  } else if (scan.kind === 'running') {
    footerDot = 'dot warn'
    footerText = `Scanning · ${runTargetLabel(scan.target)}`
  } else if (scan.kind === 'offline') {
    footerDot = 'dot bad'
    footerText = 'Backend offline'
  }

  return (
    <nav className="sidebar">
      <div className="sidebar-brand">
        <span className="logo">S</span>
        Sentinel AI
      </div>

      {NAV.map((item) => {
        const isActive = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href))
        return (
          <Link
            key={item.href}
            href={item.href}
            className={isActive ? 'active' : ''}
          >
            {item.label}
          </Link>
        )
      })}

      <div className="sidebar-footer" title={scan.kind === 'running' ? 'A scan is in progress' : undefined}>
        <span className={footerDot} />
        {footerText}
      </div>
    </nav>
  )
}
