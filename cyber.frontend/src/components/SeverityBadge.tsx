import { cn } from '@/lib/utils'
import { SEVERITY_CLASS, SEVERITY_LABEL } from '@/lib/severity'
import type { Severity } from '@/types'

const SIZE = {
  sm: 'gap-1.5 px-2 py-0.5 text-[0.65rem]',
  md: 'gap-2 px-3 py-1 text-xs',
} as const

interface SeverityBadgeProps {
  severity: Severity
  /** Appended after the label, e.g. `Critical 3`. Hidden when undefined. */
  count?: number
  size?: keyof typeof SIZE
  className?: string
}

/**
 * The single way a severity is rendered as a pill.
 *
 * Replaces `` `badge sev-${severity}` ``, which depended on five hand-written
 * CSS rules whose border colours had drifted away from the palette.
 *
 * A plain `<span>` would leave a screen reader announcing only "Critical" with
 * no indication of what that describes, so the accessible name says so
 * explicitly while the visible text stays short.
 */
export function SeverityBadge({ severity, count, size = 'md', className }: SeverityBadgeProps) {
  const tone = SEVERITY_CLASS[severity]
  const label = SEVERITY_LABEL[severity]

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border font-mono font-semibold uppercase tracking-wider whitespace-nowrap',
        SIZE[size],
        tone.text,
        tone.bg,
        tone.border,
        className,
      )}
      aria-label={count === undefined ? `${label} severity` : `${count} ${label} severity`}
    >
      {/* Decorative: the label already carries the meaning, so keep it out of
          the accessibility tree rather than announcing a bullet. */}
      <span className={cn('size-1.5 shrink-0 rounded-full', tone.fill)} aria-hidden="true" />
      {label}
      {count !== undefined && <span className="tabular-nums opacity-70">{count}</span>}
    </span>
  )
}

interface SeverityDotProps {
  severity: Severity
  className?: string
}

/**
 * Just the coloured dot, for dense rows where a full pill is too heavy - the
 * per-scan pips and the Reports legend swatches.
 */
export function SeverityDot({ severity, className }: SeverityDotProps) {
  return (
    <span
      className={cn('inline-block size-2 shrink-0 rounded-full', SEVERITY_CLASS[severity].fill, className)}
      aria-hidden="true"
    />
  )
}
