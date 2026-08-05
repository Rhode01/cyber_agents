'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'

const NAV = [
  { href: '/', label: 'Home' },
  { href: '/run', label: 'Run Agent' },
  { href: '/findings', label: 'Findings' },
  { href: '/reports', label: 'Reports' },
  { href: '/settings', label: 'Settings' },
]

export default function Sidebar() {
  const pathname = usePathname()

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

      <div className="sidebar-footer">
        <span className="dot ok" />
        Platform online
      </div>
    </nav>
  )
}
