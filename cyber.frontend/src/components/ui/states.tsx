import type { ReactNode } from 'react'

import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/utils'

/**
 * Loading, empty and error — the three states every data view needs.
 *
 * Kept in one file because they are alternatives to each other: a view picks exactly one,
 * and having them side by side makes it obvious when a new view has forgotten one. Each
 * is deliberately opinionated so a page cannot invent a fourth variant of "nothing here".
 */

/* ---------------------------------------------------------------- skeletons */

/**
 * A shimmering placeholder.
 *
 * Sized by the caller to match what will replace it. That is the whole point: a skeleton
 * whose shape differs from the real content makes the layout jump when data arrives,
 * which is worse than a spinner.
 */
export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn('skeleton-pulse rounded-sm', className)}
      aria-hidden
      data-testid="skeleton"
    />
  )
}

/** Skeleton shaped like a table: header row plus n body rows. */
export function TableSkeleton({ rows = 6, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div className="w-full" aria-busy aria-live="polite" aria-label="Loading table">
      <div className="flex gap-4 border-b border-border-subtle px-4 py-2.5">
        {Array.from({ length: columns }, (_, index) => (
          <Skeleton key={index} className={cn('h-3', index === 0 ? 'w-28' : 'w-20')} />
        ))}
      </div>
      {Array.from({ length: rows }, (_, row) => (
        <div key={row} className="flex gap-4 border-b border-border-subtle px-4 py-3">
          {Array.from({ length: columns }, (_, column) => (
            <Skeleton
              key={column}
              className={cn('h-3.5', column === 0 ? 'w-40' : column === 1 ? 'w-16' : 'w-24')}
            />
          ))}
        </div>
      ))}
    </div>
  )
}

/** Skeleton shaped like a row of stat cards. */
export function StatGridSkeleton({ count = 4 }: { count?: number }) {
  return (
    <div
      className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4"
      aria-busy
      aria-label="Loading summary"
    >
      {Array.from({ length: count }, (_, index) => (
        <div
          key={index}
          className="rounded-lg border border-border-default bg-surface-raised px-4 py-3.5"
        >
          <Skeleton className="h-2.5 w-24" />
          <Skeleton className="mt-3 h-7 w-16" />
          <Skeleton className="mt-2.5 h-2.5 w-32" />
        </div>
      ))}
    </div>
  )
}

/** Generic centred spinner, for a region with no meaningful shape to imitate. */
export function LoadingState({
  message = 'Loading',
  className,
}: {
  message?: string
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-3 px-6 py-14 text-text-tertiary',
        className,
      )}
    >
      <Spinner size="lg" label={null} />
      <p className="text-body-sm" aria-live="polite">
        {message}
      </p>
    </div>
  )
}

/* ------------------------------------------------------------------- empty */

/**
 * Nothing to show, and why.
 *
 * `title` says what is absent, `description` says why that might be, and `action` gives
 * the next step. An empty state without the second and third parts leaves the user unable
 * to tell "no data yet" from "your filter excluded everything" from "it is broken".
 */
export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
}: {
  icon?: ReactNode
  title: string
  description?: string
  action?: ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center px-6 py-14 text-center',
        className,
      )}
    >
      {icon ? (
        <div
          className={cn(
            'mb-4 flex size-11 items-center justify-center rounded-lg',
            'border border-border-subtle bg-surface-sunken text-text-tertiary',
          )}
          aria-hidden
        >
          {icon}
        </div>
      ) : null}
      <p className="text-heading font-semibold text-text-primary">{title}</p>
      {description ? (
        <p className="mt-1.5 max-w-md text-body-sm text-text-secondary">{description}</p>
      ) : null}
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  )
}

/* ------------------------------------------------------------------- error */

/**
 * Something failed, named, with a way out.
 *
 * `error` is rendered as text. Backend failures carry operator-facing detail — a missing
 * API key, a rate limit, an upstream status — and hiding that behind "Something went
 * wrong" is what makes a system feel opaque. It is deliberately shown verbatim.
 */
export function ErrorState({
  title = 'Could not load this',
  error,
  onRetry,
  icon,
  className,
}: {
  title?: string
  error?: unknown
  onRetry?: () => void
  icon?: ReactNode
  className?: string
}) {
  const detail = readErrorMessage(error)

  return (
    <div
      role="alert"
      className={cn(
        'flex flex-col items-center justify-center px-6 py-14 text-center',
        className,
      )}
    >
      {icon ? (
        <div
          className={cn(
            'mb-4 flex size-11 items-center justify-center rounded-lg',
            'border border-severity-critical/30 bg-severity-critical-bg text-severity-critical',
          )}
          aria-hidden
        >
          {icon}
        </div>
      ) : null}
      <p className="text-heading font-semibold text-text-primary">{title}</p>
      {detail ? (
        <p className="mt-1.5 max-w-lg text-body-sm break-words text-text-secondary">
          {detail}
        </p>
      ) : null}
      {onRetry ? (
        <Button variant="secondary" className="mt-5" onClick={onRetry}>
          Try again
        </Button>
      ) : null}
    </div>
  )
}

/** Compact inline variant, for a failed card inside an otherwise working page. */
export function InlineError({
  error,
  onRetry,
  className,
}: {
  error?: unknown
  onRetry?: () => void
  className?: string
}) {
  const detail = readErrorMessage(error)
  return (
    <div
      role="alert"
      className={cn(
        'flex flex-wrap items-center justify-between gap-3 rounded-md px-3 py-2.5',
        'border border-severity-critical/30 bg-severity-critical-bg',
        className,
      )}
    >
      <p className="text-body-sm break-words text-text-primary">
        {detail ?? 'This section could not be loaded.'}
      </p>
      {onRetry ? (
        <Button variant="ghost" size="sm" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  )
}

/** Pull a human-readable message out of whatever a query rejected with. */
export function readErrorMessage(error: unknown): string | null {
  if (error == null) return null
  if (typeof error === 'string') return error
  if (error instanceof Error && error.message) return error.message
  return String(error)
}
