import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

/**
 * Surfaces.
 *
 * A card is bounded by a border, never by a shadow. Elevation is reserved for things
 * that genuinely float - dialogs, dropdowns, toasts - which is what makes those read as
 * temporary. The previous design gave every panel both a shadow and a border, so nothing
 * stood out by floating and the whole page hummed.
 */

export function Card({
  children,
  className,
  as: Component = 'section',
  interactive = false,
}: {
  children: ReactNode
  className?: string
  as?: 'section' | 'div' | 'article' | 'li'
  /** Adds hover feedback. Only for cards that are themselves a link or a button. */
  interactive?: boolean
}) {
  return (
    <Component
      className={cn(
        'rounded-lg border border-border-default bg-surface-raised',
        interactive &&
          'transition-colors duration-(--duration-fast) ease-(--ease-out) ' +
            'hover:border-border-strong hover:bg-surface-raised-hover',
        className,
      )}
    >
      {children}
    </Component>
  )
}

export function CardHeader({
  title,
  description,
  actions,
  className,
  children,
}: {
  title?: ReactNode
  description?: ReactNode
  /** Right-aligned controls: filters, a menu, a "view all" link. */
  actions?: ReactNode
  className?: string
  children?: ReactNode
}) {
  return (
    <div
      className={cn(
        'flex flex-wrap items-start justify-between gap-3 border-b border-border-subtle px-4 py-3',
        className,
      )}
    >
      <div className="min-w-0">
        {title ? (
          <h2 className="text-heading font-semibold text-text-primary">{title}</h2>
        ) : null}
        {description ? (
          <p className="mt-0.5 text-body-sm text-text-secondary">{description}</p>
        ) : null}
        {children}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  )
}

export function CardBody({
  children,
  className,
  /** Turn off when the child manages its own padding - a table, for instance, which must
   *  reach the card's edges or its header row looks inset. */
  padded = true,
}: {
  children: ReactNode
  className?: string
  padded?: boolean
}) {
  return <div className={cn(padded && 'px-4 py-4', className)}>{children}</div>
}

export function CardFooter({
  children,
  className,
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex flex-wrap items-center justify-between gap-3 border-t border-border-subtle px-4 py-3',
        className,
      )}
    >
      {children}
    </div>
  )
}

/**
 * A recessed well inside a card, for quoted or untrusted content.
 *
 * Used for indicator evidence and message excerpts: the inset surface signals "this is
 * material we captured, not something we are telling you", which matters when the text
 * was written by an attacker.
 */
export function Well({
  children,
  className,
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'rounded-md border border-border-subtle bg-surface-sunken px-3 py-2',
        className,
      )}
    >
      {children}
    </div>
  )
}
