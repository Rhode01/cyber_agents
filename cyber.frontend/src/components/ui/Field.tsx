'use client'

import {
  createContext,
  useContext,
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react'

import { cn } from '@/lib/utils'

/**
 * Form controls.
 *
 * `Field` owns the label, hint and error, and hands the control its ids through context.
 * That is what makes accessibility automatic rather than per-form: the input always gets
 * `aria-describedby` pointing at its hint, `aria-invalid` when there is an error, and a
 * label whose `htmlFor` actually matches. Every form in the old design wired this by hand,
 * which mostly meant not wiring it.
 */

interface FieldContextValue {
  inputId: string
  hintId?: string
  errorId?: string
  invalid: boolean
}

const FieldContext = createContext<FieldContextValue | null>(null)

function useFieldContext() {
  return useContext(FieldContext)
}

export function Field({
  label,
  hint,
  error,
  required = false,
  children,
  className,
  /** Hides the label visually but keeps it for screen readers. For a control whose purpose
   *  is obvious from context, such as a search box with a magnifier. */
  labelHidden = false,
}: {
  label: string
  hint?: ReactNode
  error?: string | null
  required?: boolean
  children: ReactNode
  className?: string
  labelHidden?: boolean
}) {
  const base = useId()
  const inputId = `${base}-input`
  const hintId = hint ? `${base}-hint` : undefined
  const errorId = error ? `${base}-error` : undefined

  return (
    <FieldContext.Provider value={{ inputId, hintId, errorId, invalid: Boolean(error) }}>
      <div className={cn('flex flex-col gap-1.5', className)}>
        <label
          htmlFor={inputId}
          className={cn(
            'text-label font-medium text-text-secondary',
            labelHidden && 'sr-only',
          )}
        >
          {label}
          {required ? (
            <span className="ml-1 text-severity-critical" aria-hidden>
              *
            </span>
          ) : null}
        </label>

        {children}

        {/* Hint before error in the DOM, but the error wins visually when both exist. */}
        {hint && !error ? (
          <p id={hintId} className="text-caption leading-4 text-text-tertiary">
            {hint}
          </p>
        ) : null}
        {error ? (
          <p id={errorId} className="text-caption leading-4 text-severity-critical">
            {error}
          </p>
        ) : null}
      </div>
    </FieldContext.Provider>
  )
}

const CONTROL_BASE =
  'w-full rounded-md border bg-surface-sunken px-3 text-body text-text-primary ' +
  'transition-colors duration-(--duration-fast) ease-(--ease-out) ' +
  'placeholder:text-text-tertiary ' +
  'disabled:cursor-not-allowed disabled:opacity-60'

const CONTROL_BORDER =
  'border-border-default hover:border-border-strong ' +
  'focus:border-accent focus:outline-none focus-visible:outline-none'

const CONTROL_INVALID = 'border-severity-critical/60 hover:border-severity-critical'

/** Wires a control to its Field. Exported so a bespoke control can behave like the rest. */
export function useFieldProps() {
  const field = useFieldContext()
  if (!field) return {}
  return {
    id: field.inputId,
    'aria-invalid': field.invalid || undefined,
    'aria-describedby':
      [field.errorId, field.hintId].filter(Boolean).join(' ') || undefined,
  }
}

export function Input({
  className,
  leading,
  trailing,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & {
  /** Icon or affix inside the control, left side. */
  leading?: ReactNode
  trailing?: ReactNode
}) {
  const fieldProps = useFieldProps()
  const invalid = fieldProps['aria-invalid']

  const control = (
    <input
      {...fieldProps}
      {...rest}
      className={cn(
        CONTROL_BASE,
        invalid ? CONTROL_INVALID : CONTROL_BORDER,
        'h-9',
        leading && 'pl-9',
        trailing && 'pr-9',
        className,
      )}
    />
  )

  if (!leading && !trailing) return control

  return (
    <div className="relative">
      {leading ? (
        <span
          className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-tertiary"
          aria-hidden
        >
          {leading}
        </span>
      ) : null}
      {control}
      {trailing ? (
        <span className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-tertiary">
          {trailing}
        </span>
      ) : null}
    </div>
  )
}

export function Textarea({
  className,
  rows = 4,
  ...rest
}: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const fieldProps = useFieldProps()
  return (
    <textarea
      {...fieldProps}
      {...rest}
      rows={rows}
      className={cn(
        CONTROL_BASE,
        fieldProps['aria-invalid'] ? CONTROL_INVALID : CONTROL_BORDER,
        'resize-y py-2 leading-5',
        className,
      )}
    />
  )
}

/**
 * Native select.
 *
 * Native rather than a custom listbox on purpose: it is keyboard- and screen-reader-correct
 * for free, and it gives the platform picker on mobile. The custom `Select` built on Radix
 * is reserved for cases that need option descriptions or icons.
 */
export function NativeSelect({
  className,
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement>) {
  const fieldProps = useFieldProps()
  return (
    <div className="relative">
      <select
        {...fieldProps}
        {...rest}
        className={cn(
          CONTROL_BASE,
          fieldProps['aria-invalid'] ? CONTROL_INVALID : CONTROL_BORDER,
          'h-9 appearance-none pr-8',
          className,
        )}
      >
        {children}
      </select>
      {/* Caret. A CSS triangle rather than an icon import, so this control stays
          dependency-free like the rest of this file. */}
      <span
        aria-hidden
        className={cn(
          'pointer-events-none absolute right-3 top-1/2 -mt-px size-0 -translate-y-1/2',
          'border-x-4 border-t-[5px] border-x-transparent border-t-text-tertiary',
        )}
      />
    </div>
  )
}

export function Checkbox({
  label,
  description,
  className,
  ...rest
}: Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & {
  label: ReactNode
  description?: ReactNode
}) {
  const generated = useId()
  const id = rest.id ?? generated
  const descriptionId = description ? `${id}-description` : undefined

  return (
    <div className={cn('flex items-start gap-2.5', className)}>
      <input
        {...rest}
        id={id}
        type="checkbox"
        aria-describedby={descriptionId}
        className={cn(
          'mt-0.5 size-4 shrink-0 cursor-pointer appearance-none rounded-sm',
          'border border-border-strong bg-surface-sunken',
          'transition-colors duration-(--duration-fast)',
          'checked:border-accent checked:bg-accent',
          // The tick is a rotated pseudo-border, so there is no icon dependency and it
          // scales with the box.
          'relative checked:after:absolute checked:after:left-[4px] checked:after:top-[1px]',
          'checked:after:h-[8px] checked:after:w-[4px] checked:after:rotate-45',
          'checked:after:border-b-2 checked:after:border-r-2 checked:after:border-accent-contrast',
          'checked:after:content-[""]',
          'disabled:cursor-not-allowed disabled:opacity-60',
        )}
      />
      <div className="min-w-0">
        <label htmlFor={id} className="cursor-pointer text-body text-text-primary">
          {label}
        </label>
        {description ? (
          <p id={descriptionId} className="mt-0.5 text-caption leading-4 text-text-tertiary">
            {description}
          </p>
        ) : null}
      </div>
    </div>
  )
}

/** Checkbox styled as a toggle, for settings that take effect immediately. */
export function Switch({
  label,
  description,
  className,
  ...rest
}: Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & {
  label: ReactNode
  description?: ReactNode
}) {
  const generated = useId()
  const id = rest.id ?? generated
  const descriptionId = description ? `${id}-description` : undefined

  return (
    <div className={cn('flex items-start justify-between gap-4', className)}>
      <div className="min-w-0">
        <label htmlFor={id} className="cursor-pointer text-body text-text-primary">
          {label}
        </label>
        {description ? (
          <p id={descriptionId} className="mt-0.5 text-caption leading-4 text-text-tertiary">
            {description}
          </p>
        ) : null}
      </div>
      <input
        {...rest}
        id={id}
        type="checkbox"
        role="switch"
        aria-describedby={descriptionId}
        className={cn(
          'relative h-5 w-9 shrink-0 cursor-pointer appearance-none rounded-full',
          'border border-border-strong bg-surface-sunken',
          'transition-colors duration-(--duration-base) ease-(--ease-out)',
          'checked:border-accent checked:bg-accent',
          'after:absolute after:left-0.5 after:top-1/2 after:size-3.5 after:-translate-y-1/2',
          'after:rounded-full after:bg-text-secondary after:transition-transform',
          'after:duration-(--duration-base) after:ease-(--ease-out) after:content-[""]',
          'checked:after:translate-x-4 checked:after:bg-accent-contrast',
          'disabled:cursor-not-allowed disabled:opacity-60',
        )}
      />
    </div>
  )
}
