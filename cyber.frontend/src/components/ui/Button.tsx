import Link from 'next/link'
import type { ButtonHTMLAttributes, ReactNode } from 'react'

import { Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/utils'

/**
 * The single button implementation.
 *
 * Icons arrive as props rather than being imported here, so this primitive has no
 * dependency on the icon library and cannot quietly become a place where icon choices
 * are made. Callers pass `<Play className="size-4" />`.
 */

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'
export type ButtonSize = 'sm' | 'md' | 'lg'

const VARIANT: Record<ButtonVariant, string> = {
  primary:
    'bg-accent text-accent-contrast hover:bg-accent-hover active:bg-accent-active ' +
    'disabled:bg-accent/40',
  secondary:
    'bg-surface-raised text-text-primary border border-border-default ' +
    'hover:bg-surface-raised-hover hover:border-border-strong',
  ghost: 'text-text-secondary hover:bg-surface-raised hover:text-text-primary',
  // Destructive actions are outlined until hover rather than permanently red: a row of
  // solid red buttons reads as an alarm state rather than as available actions.
  danger:
    'text-severity-critical border border-severity-critical/40 ' +
    'hover:bg-severity-critical-bg hover:border-severity-critical/70',
}

const SIZE: Record<ButtonSize, string> = {
  sm: 'h-8 px-2.5 gap-1.5 text-label rounded-sm',
  md: 'h-9 px-3 gap-2 text-body rounded-md',
  lg: 'h-10 px-4 gap-2 text-body rounded-md',
}

const BASE =
  'inline-flex items-center justify-center font-medium whitespace-nowrap select-none ' +
  'transition-colors duration-(--duration-fast) ease-(--ease-out) ' +
  'disabled:cursor-not-allowed disabled:opacity-60'

interface CommonProps {
  variant?: ButtonVariant
  size?: ButtonSize
  leadingIcon?: ReactNode
  trailingIcon?: ReactNode
  /** Swaps the leading icon for a spinner, disables the control and sets aria-busy. */
  loading?: boolean
  fullWidth?: boolean
  children?: ReactNode
  className?: string
}

type NativeButtonProps = CommonProps &
  Omit<ButtonHTMLAttributes<HTMLButtonElement>, keyof CommonProps> & { href?: undefined }

type LinkButtonProps = CommonProps & {
  /** Renders a Next.js Link styled as a button. */
  href: string
  external?: boolean
}

export type ButtonProps = NativeButtonProps | LinkButtonProps

export function Button(props: ButtonProps) {
  const {
    variant = 'secondary',
    size = 'md',
    leadingIcon,
    trailingIcon,
    loading = false,
    fullWidth = false,
    children,
    className,
  } = props

  const classes = cn(BASE, VARIANT[variant], SIZE[size], fullWidth && 'w-full', className)

  const content = (
    <>
      {loading ? <Spinner size="xs" label={null} /> : leadingIcon}
      {children}
      {trailingIcon}
    </>
  )

  if ('href' in props && props.href !== undefined) {
    const { href, external } = props
    return (
      <Link
        href={href}
        className={classes}
        {...(external ? { target: '_blank', rel: 'noreferrer noopener' } : {})}
      >
        {content}
      </Link>
    )
  }

  // Strip the props this component consumes so the rest can spread onto the DOM node without
  // React warning about unknown attributes. Written as an omit rather than a destructure with
  // nine throwaway bindings, which reads as nine mistakes to both a linter and a reader.
  const rest = omit(props as NativeButtonProps, [
    'variant',
    'size',
    'leadingIcon',
    'trailingIcon',
    'loading',
    'fullWidth',
    'children',
    'className',
    'href',
  ])

  return (
    <button
      type="button"
      className={classes}
      disabled={rest.disabled || loading}
      aria-busy={loading || undefined}
      {...rest}
    >
      {content}
    </button>
  )
}

export interface IconButtonProps
  extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
  /** Required. An icon-only control with no accessible name is unusable by screen
   *  reader and unlabelled on hover. */
  label: string
  icon: ReactNode
  variant?: ButtonVariant
  size?: Exclude<ButtonSize, 'lg'>
  loading?: boolean
  className?: string
}

const ICON_SIZE: Record<Exclude<ButtonSize, 'lg'>, string> = {
  sm: 'size-7 rounded-sm',
  md: 'size-9 rounded-md',
}

export function IconButton({
  label,
  icon,
  variant = 'ghost',
  size = 'md',
  loading = false,
  className,
  ...rest
}: IconButtonProps) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cn(BASE, VARIANT[variant], ICON_SIZE[size], 'px-0', className)}
      disabled={rest.disabled || loading}
      aria-busy={loading || undefined}
      {...rest}
    >
      {loading ? <Spinner size="xs" label={null} /> : icon}
    </button>
  )
}

/**
 * Copy an object without the named keys.
 *
 * Local rather than reached for from a utility library: the only need is stripping design-system
 * props before a DOM spread, and a dependency for nine `delete`s is not a trade worth making.
 */
function omit<T extends object, K extends keyof T>(source: T, keys: readonly K[]): Omit<T, K> {
  const copy = { ...source }
  for (const key of keys) delete copy[key]
  return copy
}

/** Segmented group. Collapses the borders between adjacent buttons. */
export function ButtonGroup({
  children,
  className,
  label,
}: {
  children: ReactNode
  className?: string
  label: string
}) {
  return (
    <div
      role="group"
      aria-label={label}
      className={cn(
        'inline-flex items-center rounded-md border border-border-default',
        'divide-x divide-border-default overflow-hidden',
        '[&>*]:rounded-none [&>*]:border-0',
        className,
      )}
    >
      {children}
    </div>
  )
}
