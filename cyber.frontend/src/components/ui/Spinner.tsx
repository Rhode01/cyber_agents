import { cn } from '@/lib/utils'

const SIZE = {
  xs: 'size-3 border',
  sm: 'size-4 border-2',
  md: 'size-5 border-2',
  lg: 'size-8 border-2',
} as const

export interface SpinnerProps {
  size?: keyof typeof SIZE
  className?: string
  /** Announced to screen readers. Set to null on a spinner that sits inside an
   *  already-labelled control, so it is not read twice. */
  label?: string | null
}

/**
 * The one indeterminate progress indicator.
 *
 * Built from a rotating border rather than an SVG or an icon-library glyph: it needs no
 * dependency, scales with `currentColor`, and there is exactly one of it so every
 * spinner in the app turns at the same speed.
 */
export function Spinner({ size = 'sm', className, label = 'Loading' }: SpinnerProps) {
  return (
    <span
      className={cn(
        'inline-block shrink-0 animate-spin rounded-full',
        'border-current border-t-transparent',
        SIZE[size],
        className,
      )}
      role={label ? 'status' : undefined}
      aria-hidden={label ? undefined : true}
    >
      {label ? <span className="sr-only">{label}</span> : null}
    </span>
  )
}
