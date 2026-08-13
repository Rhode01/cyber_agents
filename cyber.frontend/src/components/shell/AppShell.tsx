'use client'

import { useState, type ReactNode } from 'react'

import { COLLAPSE_KEY, Sidebar } from '@/components/shell/Sidebar'
import { Topbar } from '@/components/shell/Topbar'
import { TooltipProvider } from '@/components/ui/overlays'
import { useStoredFlag } from '@/lib/useStoredFlag'
import { cn } from '@/lib/utils'

/**
 * The frame every page sits in.
 *
 * A client component because the sidebar's collapsed and mobile-open state lives here — the
 * root layout stays a server component so the tree is not needlessly opted out of server
 * rendering.
 *
 * The left margin matches the sidebar width and is applied from `lg` up only. Below that the
 * sidebar is an overlay drawer, so the content is full-width rather than squeezed.
 */
export function AppShell({ children }: { children: ReactNode }) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  /* Collapsed state lives here rather than in the Sidebar because the content's left margin
     depends on it. A CSS-only version is not available: the nav is a *previous sibling* of
     the content, and `:has()` matches descendants, so nothing can select "the div after a
     collapsed nav". */
  const [collapsed, setCollapsed] = useStoredFlag(COLLAPSE_KEY)

  return (
    <TooltipProvider>
      {/* Keyboard users should not have to tab the whole nav to reach the page. */}
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-contrast"
      >
        Skip to content
      </a>

      <Sidebar
        collapsed={collapsed}
        onToggleCollapsed={() => setCollapsed(!collapsed)}
        mobileOpen={mobileNavOpen}
        onMobileClose={() => setMobileNavOpen(false)}
      />

      <div
        className={cn(
          'lg:transition-[margin] lg:duration-(--duration-base) lg:ease-(--ease-out)',
          collapsed ? 'lg:ml-[4.25rem]' : 'lg:ml-60',
        )}
      >
        <Topbar onOpenNav={() => setMobileNavOpen(true)} />
        <main id="main" className="px-4 py-6 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-[92rem]">{children}</div>
        </main>
      </div>
    </TooltipProvider>
  )
}
