import Link from 'next/link'
import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

/**
 * The top of every page, so no two pages introduce themselves differently.
 *
 * Previously each page hand-rolled its own title block with its own margins and its own
 * idea of where the primary action goes. One component means the eye lands in the same
 * place on every route.
 */

export interface Crumb {
  label: string
  href?: string
}

export function Breadcrumbs({ items }: { items: readonly Crumb[] }) {
  if (items.length === 0) return null

  return (
    <nav aria-label="Breadcrumb">
      <ol className="flex flex-wrap items-center gap-1.5 text-caption text-text-tertiary">
        {items.map((crumb, index) => {
          const last = index === items.length - 1
          return (
            <li key={`${crumb.label}-${index}`} className="flex items-center gap-1.5">
              {crumb.href && !last ? (
                <Link
                  href={crumb.href}
                  className="transition-colors hover:text-text-secondary"
                >
                  {crumb.label}
                </Link>
              ) : (
                <span aria-current={last ? 'page' : undefined} className={cn(last && 'text-text-secondary')}>
                  {crumb.label}
                </span>
              )}
              {!last ? (
                <span aria-hidden className="text-border-strong">
                  /
                </span>
              ) : null}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}

export function PageHeader({
  title,
  description,
  breadcrumbs,
  actions,
  meta,
  className,
}: {
  title: string
  description?: string
  breadcrumbs?: readonly Crumb[]
  /** Primary and secondary actions, right-aligned. Primary goes last. */
  actions?: ReactNode
  /** Badges or status chips that qualify the title. */
  meta?: ReactNode
  className?: string
}) {
  return (
    <header className={cn('mb-6', className)}>
      {breadcrumbs && breadcrumbs.length > 0 ? (
        <div className="mb-2">
          <Breadcrumbs items={breadcrumbs} />
        </div>
      ) : null}
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-display font-semibold text-text-primary">{title}</h1>
            {meta}
          </div>
          {description ? (
            <p className="mt-1.5 max-w-2xl text-body text-text-secondary">{description}</p>
          ) : null}
        </div>
        {actions ? (
          <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>
        ) : null}
      </div>
    </header>
  )
}

/**
 * A heading between sections of one page.
 *
 * Smaller than a page title and larger than a card title, so a page can have structure
 * without every group of content becoming a card. Overusing cards is what made the old
 * dashboard read as a pile of boxes.
 */
export function SectionHeader({
  title,
  description,
  actions,
  className,
}: {
  title: string
  description?: string
  actions?: ReactNode
  className?: string
}) {
  return (
    <div
      className={cn('mb-3 flex flex-wrap items-end justify-between gap-x-4 gap-y-2', className)}
    >
      <div className="min-w-0">
        <h2 className="text-title font-semibold text-text-primary">{title}</h2>
        {description ? (
          <p className="mt-1 text-body-sm text-text-secondary">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  )
}

/**
 * An all-caps micro-label above a value or group.
 *
 * The one place the old design's `.eyebrow` was genuinely useful, kept as a component so
 * its letter-spacing and colour cannot drift.
 */
export function Eyebrow({
  children,
  className,
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <p
      className={cn(
        'text-caption font-medium uppercase tracking-wide text-text-tertiary',
        className,
      )}
    >
      {children}
    </p>
  )
}
