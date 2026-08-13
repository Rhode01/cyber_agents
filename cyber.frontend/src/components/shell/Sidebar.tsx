'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useEffect } from 'react'

import { IconButton } from '@/components/ui/Button'
import { ChevronRight, Shield, X } from '@/components/ui/icons'
import { Hint } from '@/components/ui/overlays'
import { NAV_GROUPS, isActive } from '@/components/shell/navigation'
import { cn } from '@/lib/utils'

/** Exported so `AppShell`, which owns the state, reads and writes the same key. */
export const COLLAPSE_KEY = 'sentinel:sidebar-collapsed'

/**
 * Primary navigation.
 *
 * Collapses to an icon rail on demand and to an off-canvas drawer below `lg`. The old
 * sidebar was a fixed 240px at every width, so on a tablet it took a quarter of the screen
 * away from the tables it was navigating to.
 *
 * It also used to poll `/runs/status` every four seconds on its own, on every route. That
 * moved to a shared query consumed by the topbar, which is the only place it is displayed.
 */
export function Sidebar({
  collapsed,
  onToggleCollapsed,
  mobileOpen,
  onMobileClose,
}: {
  /** Owned by `AppShell`, because the content margin depends on it too. */
  collapsed: boolean
  onToggleCollapsed: () => void
  mobileOpen: boolean
  onMobileClose: () => void
}) {
  const pathname = usePathname()

  // Any navigation closes the mobile drawer; otherwise it stays over the page you asked for.
  useEffect(() => {
    onMobileClose()
  }, [pathname, onMobileClose])

  return (
    <>
      {/* Scrim, below lg only. */}
      {mobileOpen ? (
        <button
          type="button"
          aria-label="Close navigation"
          onClick={onMobileClose}
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
        />
      ) : null}

      <nav
        aria-label="Main"
        data-collapsed={collapsed || undefined}
        className={cn(
          'fixed inset-y-0 left-0 z-40 flex flex-col border-r border-border-default',
          'bg-surface-sunken transition-[width,transform] duration-(--duration-base) ease-(--ease-out)',
          collapsed ? 'w-[4.25rem]' : 'w-60',
          // Off-canvas below lg, always present from lg up.
          mobileOpen ? 'translate-x-0' : '-translate-x-full',
          'lg:translate-x-0',
        )}
      >
        <div
          className={cn(
            'flex h-14 shrink-0 items-center gap-2.5 border-b border-border-subtle px-4',
            collapsed && 'justify-center px-0',
          )}
        >
          <span
            className="flex size-7 shrink-0 items-center justify-center rounded-md bg-accent text-accent-contrast"
            aria-hidden
          >
            <Shield className="size-4" strokeWidth={2.25} />
          </span>
          {!collapsed ? (
            <span className="truncate font-display text-body font-semibold tracking-tight">
              Sentinel AI
            </span>
          ) : null}
          <span className="ml-auto lg:hidden">
            <IconButton
              label="Close navigation"
              icon={<X className="size-4" />}
              size="sm"
              onClick={onMobileClose}
            />
          </span>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto py-3">
          {NAV_GROUPS.map((group) => (
            <div key={group.id} className="mb-4 last:mb-0">
              {!collapsed ? (
                <p className="mb-1 px-4 text-caption font-medium uppercase tracking-wide text-text-tertiary">
                  {group.label}
                </p>
              ) : (
                // A rule instead of a heading, so the grouping survives collapse.
                <div className="mx-4 mb-2 h-px bg-border-subtle" aria-hidden />
              )}

              <ul className={cn('space-y-0.5', collapsed ? 'px-2.5' : 'px-2')}>
                {group.routes.map((route) => {
                  const active = isActive(route.href, pathname)
                  const Icon = route.icon

                  const item = (
                    <Link
                      href={route.href}
                      aria-current={active ? 'page' : undefined}
                      className={cn(
                        'flex items-center gap-2.5 rounded-md text-body-sm font-medium',
                        'transition-colors duration-(--duration-fast)',
                        collapsed ? 'justify-center p-2.5' : 'px-2.5 py-2',
                        active
                          ? 'bg-accent-surface text-text-primary'
                          : 'text-text-secondary hover:bg-surface-raised hover:text-text-primary',
                      )}
                    >
                      <Icon
                        className={cn('size-4 shrink-0', active && 'text-accent')}
                        aria-hidden
                      />
                      {!collapsed ? <span className="truncate">{route.label}</span> : null}
                    </Link>
                  )

                  return (
                    <li key={route.href}>
                      {collapsed ? (
                        <Hint content={route.label} side="right">
                          {item}
                        </Hint>
                      ) : (
                        item
                      )}
                    </li>
                  )
                })}
              </ul>
            </div>
          ))}
        </div>

        {/* Collapse control. Hidden below lg, where the drawer already handles width. */}
        <div className="hidden shrink-0 border-t border-border-subtle p-2 lg:block">
          <button
            type="button"
            onClick={onToggleCollapsed}
            aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
            className={cn(
              'flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-body-sm',
              'text-text-tertiary transition-colors hover:bg-surface-raised hover:text-text-secondary',
              collapsed && 'justify-center px-0',
            )}
          >
            <ChevronRight
              className={cn(
                'size-4 shrink-0 transition-transform duration-(--duration-base)',
                !collapsed && 'rotate-180',
              )}
              aria-hidden
            />
            {!collapsed ? <span>Collapse</span> : null}
          </button>
        </div>
      </nav>
    </>
  )
}
