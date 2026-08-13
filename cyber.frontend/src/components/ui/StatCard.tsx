import Link from 'next/link'
import type { ReactNode } from 'react'

import { Eyebrow } from '@/components/ui/PageHeader'
import { cn } from '@/lib/utils'

/**
 * A single headline metric.
 *
 * Deliberately narrow in what it offers: a label, a value, one optional qualifier, and one
 * optional trend. The old dashboard's stat cards each grew their own extra line, so four
 * cards in a row had four different heights and four different type treatments.
 *
 * `tone` colours the *value only*, never the card. A row of tinted cards competes for
 * attention and then none of them wins.
 */

export type StatTone = 'default' | 'critical' | 'high' | 'medium' | 'low' | 'ok' | 'accent'

const VALUE_TONE: Record<StatTone, string> = {
  default: 'text-text-primary',
  critical: 'text-severity-critical',
  high: 'text-severity-high',
  medium: 'text-severity-medium',
  low: 'text-severity-low',
  ok: 'text-status-ok',
  accent: 'text-accent',
}

export interface StatCardProps {
  label: string
  /** Pre-formatted. This component does not know your units. */
  value: ReactNode
  /** One short line: a comparison, a breakdown, or a timestamp. */
  hint?: ReactNode
  tone?: StatTone
  icon?: ReactNode
  /** Turns the whole card into a link through to the filtered view behind the number. */
  href?: string
  className?: string
}

export function StatCard({
  label,
  value,
  hint,
  tone = 'default',
  icon,
  href,
  className,
}: StatCardProps) {
  const body = (
    <>
      <div className="flex items-start justify-between gap-3">
        <Eyebrow>{label}</Eyebrow>
        {icon ? (
          <span className="shrink-0 text-text-tertiary" aria-hidden>
            {icon}
          </span>
        ) : null}
      </div>
      <p
        className={cn(
          'mt-2 font-display text-[1.75rem] leading-9 font-semibold',
          VALUE_TONE[tone],
        )}
        data-numeric
      >
        {value}
      </p>
      {hint ? (
        <p className="mt-1 text-body-sm text-text-secondary">{hint}</p>
      ) : null}
    </>
  )

  const classes = cn(
    'block rounded-lg border border-border-default bg-surface-raised px-4 py-3.5',
    href &&
      'transition-colors duration-(--duration-fast) ease-(--ease-out) ' +
        'hover:border-border-strong hover:bg-surface-raised-hover',
    className,
  )

  if (href) {
    return (
      <Link href={href} className={classes}>
        {body}
      </Link>
    )
  }

  return <div className={classes}>{body}</div>
}

/**
 * Equal-width row of stat cards.
 *
 * A component rather than a repeated grid class so every page's summary row breaks at the
 * same widths.
 */
export function StatGrid({
  children,
  className,
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <div className={cn('grid gap-4 sm:grid-cols-2 xl:grid-cols-4', className)}>
      {children}
    </div>
  )
}
