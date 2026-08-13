'use client'

import { useIsFetching, useQueryClient } from '@tanstack/react-query'
import { usePathname } from 'next/navigation'

import { Badge, Dot } from '@/components/ui/Badge'
import { IconButton } from '@/components/ui/Button'
import { Activity, Layers, RefreshCw } from '@/components/ui/icons'
import { Hint } from '@/components/ui/overlays'
import { routeForPath } from '@/components/shell/navigation'
import { useMessages, useRunStatus, useSystemModules } from '@/lib/queries'
import { cn } from '@/lib/utils'

/**
 * The bar across the top of every page.
 *
 * It answers two questions an analyst asks constantly and which the old UI answered only on
 * the pages that happened to fetch them: is the platform healthy, and is anything running
 * right now. Both come from shared queries, so this bar costs one poll for the whole app
 * rather than one per page.
 */
export function Topbar({ onOpenNav }: { onOpenNav: () => void }) {
  const pathname = usePathname()
  const route = routeForPath(pathname)

  const queryClient = useQueryClient()
  // Any in-flight request anywhere, so the refresh control spins for what it actually triggers.
  const fetching = useIsFetching()

  const modules = useSystemModules()
  const runStatus = useRunStatus()
  // Non-terminal intakes are work in flight the user should be able to see from anywhere.
  const messages = useMessages({ limit: 20 })

  const down = (modules.data?.items ?? []).filter((module) => module.status !== 'ok')
  const inFlightMessages = (messages.data?.items ?? []).filter(
    (message) => message.status !== 'completed' && message.status !== 'failed',
  ).length
  const scanning = runStatus.data?.scanning ?? false
  const busy = scanning || inFlightMessages > 0

  return (
    <header
      className={cn(
        'sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-border-default',
        'bg-surface-page/90 px-4 backdrop-blur-sm sm:px-6',
      )}
    >
      <span className="lg:hidden">
        <IconButton
          label="Open navigation"
          icon={<Layers className="size-4" />}
          size="sm"
          variant="secondary"
          onClick={onOpenNav}
        />
      </span>

      {/* The current page, so the title is visible even when scrolled past the header. */}
      <p className="min-w-0 truncate font-display text-body font-semibold text-text-primary">
        {route?.title ?? 'Sentinel AI'}
      </p>

      <div className="ml-auto flex items-center gap-2">
        {busy ? (
          <Badge tone="active" icon={<Dot tone="active" pulse />}>
            {scanning && inFlightMessages > 0
              ? `Scan + ${inFlightMessages} analysing`
              : scanning
                ? 'Scan running'
                : `${inFlightMessages} analysing`}
          </Badge>
        ) : null}

        <Hint
          content={
            modules.isError
              ? 'The backend could not be reached, so module health is unknown.'
              : down.length === 0
                ? 'Database, queue, ai.engine and MCP server all responding.'
                : `Not responding: ${down.map((module) => module.name).join(', ')}.`
          }
        >
          {/* A button, not a div: a tooltip that cannot be reached by keyboard is
              information only mouse users get. */}
          <button
            type="button"
            className="flex items-center gap-1.5 rounded-md px-2 py-1.5 text-caption text-text-tertiary transition-colors hover:bg-surface-raised hover:text-text-secondary"
          >
            <Activity className="size-3.5" aria-hidden />
            {modules.isError ? (
              <>
                <Dot tone="error" />
                <span>Backend unreachable</span>
              </>
            ) : down.length === 0 ? (
              <>
                <Dot tone="ok" />
                <span>All systems</span>
              </>
            ) : (
              <>
                <Dot tone="warn" />
                <span>
                  <span data-numeric>{down.length}</span> degraded
                </span>
              </>
            )}
          </button>
        </Hint>

        <Hint content="Refresh everything on screen">
          <IconButton
            label="Refresh"
            size="sm"
            icon={
              <RefreshCw
                className={cn(
                  'size-4',
                  fetching > 0 && 'animate-spin motion-reduce:animate-none',
                )}
                aria-hidden
              />
            }
            /* Invalidates the whole cache rather than the three queries this bar happens to
               hold. The tooltip promises the data on screen, and refetching only the health
               chip while leaving a stale findings table underneath would make it a lie. */
            onClick={() => void queryClient.invalidateQueries()}
          />
        </Hint>
      </div>
    </header>
  )
}
