import type { ReactNode } from 'react'

import { SEVERITY_ICON } from '@/components/ui/icons'
import { SEVERITY_CLASS, SEVERITY_LABEL } from '@/lib/severity'
import { cn } from '@/lib/utils'
import type { Severity } from '@/types'

/**
 * Every pill in the application.
 *
 * There used to be three overlapping treatments — `SeverityBadge`, `FindingTypeChip`, and
 * `.pill`/`.sev-*` in CSS — which is why `info` rendered magenta on one page and grey on
 * another. This is the single implementation; `lib/severity.ts` and `lib/findings.ts`
 * remain the source of the labels and class maps.
 *
 * Severity and status are **never colour alone**. Each badge carries its label as text, so
 * it survives colour blindness, greyscale printing, and the reader who simply does not
 * know that orange means high.
 */

export type BadgeTone =
  | 'neutral'
  | 'accent'
  | 'ok'
  | 'warn'
  | 'error'
  | 'active'

const TONE: Record<BadgeTone, string> = {
  neutral: 'text-text-secondary bg-status-neutral-bg border-status-neutral/25',
  accent: 'text-accent bg-accent-surface border-accent-border',
  ok: 'text-status-ok bg-status-ok-bg border-status-ok/25',
  warn: 'text-status-warn bg-status-warn-bg border-status-warn/25',
  error: 'text-status-error bg-status-error-bg border-status-error/25',
  active: 'text-status-active bg-status-active-bg border-status-active/25',
}

const SIZE = {
  sm: 'h-5 px-1.5 gap-1 text-caption',
  md: 'h-6 px-2 gap-1.5 text-label',
} as const

const BASE =
  'inline-flex items-center rounded-full border font-medium whitespace-nowrap align-middle'

export interface BadgeProps {
  children: ReactNode
  tone?: BadgeTone
  size?: keyof typeof SIZE
  icon?: ReactNode
  className?: string
}

export function Badge({
  children,
  tone = 'neutral',
  size = 'md',
  icon,
  className,
}: BadgeProps) {
  return (
    <span className={cn(BASE, TONE[tone], SIZE[size], className)}>
      {icon ? (
        <span className="shrink-0" aria-hidden>
          {icon}
        </span>
      ) : null}
      {children}
    </span>
  )
}

/**
 * Severity, the most repeated element in the product.
 *
 * Colours come from `SEVERITY_CLASS`, whose class strings are written out literally
 * because Tailwind v4 scans for literals — an interpolated `bg-severity-${severity}`
 * generates no CSS at all.
 */
export function SeverityBadge({
  severity,
  count,
  size = 'md',
  showIcon = true,
  className,
}: {
  severity: Severity
  /** Renders as "Critical · 12". Used in tallies and filter chips. */
  count?: number
  size?: keyof typeof SIZE
  /** Off only where the row already carries a severity icon in another column. */
  showIcon?: boolean
  className?: string
}) {
  const style = SEVERITY_CLASS[severity]
  const Icon = SEVERITY_ICON[severity]

  return (
    <span
      className={cn(BASE, SIZE[size], style.text, style.bg, style.border, className)}
      title={`${SEVERITY_LABEL[severity]} severity`}
    >
      {showIcon ? (
        <Icon className={size === 'sm' ? 'size-3 shrink-0' : 'size-3.5 shrink-0'} aria-hidden />
      ) : null}
      {SEVERITY_LABEL[severity]}
      {count !== undefined ? (
        <>
          <span aria-hidden className="opacity-40">
            ·
          </span>
          <span data-numeric>{count}</span>
        </>
      ) : null}
    </span>
  )
}

/**
 * A coloured pip. Only ever alongside a text label — on its own it is exactly the
 * colour-only signalling this component set exists to remove.
 */
export function Dot({
  tone = 'neutral',
  pulse = false,
  className,
}: {
  tone?: BadgeTone | 'critical' | 'high' | 'medium' | 'low' | 'info'
  /** For genuinely live state, e.g. work in flight. Nothing else. */
  pulse?: boolean
  className?: string
}) {
  const FILL: Record<string, string> = {
    neutral: 'bg-status-neutral',
    accent: 'bg-accent',
    ok: 'bg-status-ok',
    warn: 'bg-status-warn',
    error: 'bg-status-error',
    active: 'bg-status-active',
    critical: 'bg-severity-critical',
    high: 'bg-severity-high',
    medium: 'bg-severity-medium',
    low: 'bg-severity-low',
    info: 'bg-severity-info',
  }
  return (
    <span className={cn('relative inline-flex shrink-0', className)} aria-hidden>
      <span className={cn('size-1.5 rounded-full', FILL[tone])} />
      {pulse ? (
        <span
          className={cn(
            'absolute inset-0 animate-ping rounded-full opacity-60',
            FILL[tone],
          )}
        />
      ) : null}
    </span>
  )
}

/**
 * A count that means "how many, and how bad".
 *
 * Used in table cells and card headers where a full row of severity badges would not fit.
 * Zero-count severities are dropped rather than shown as "0", because a row of zeros
 * carries no information and costs a line of width.
 */
export function SeverityTally({
  counts,
  order,
  size = 'sm',
  className,
}: {
  counts: Record<Severity, number>
  order: readonly Severity[]
  size?: keyof typeof SIZE
  className?: string
}) {
  const present = order.filter((severity) => counts[severity] > 0)

  if (present.length === 0) {
    return <span className="text-body-sm text-text-tertiary">None</span>
  }

  return (
    <span className={cn('inline-flex flex-wrap items-center gap-1', className)}>
      {present.map((severity) => (
        <SeverityBadge
          key={severity}
          severity={severity}
          count={counts[severity]}
          size={size}
        />
      ))}
    </span>
  )
}
