'use client'

import { useId, useRef, useState, type DragEvent } from 'react'

import { FileUp, X } from '@/components/ui/icons'
import { IconButton } from '@/components/ui/Button'
import { cn } from '@/lib/utils'

/**
 * File selection, by drop or by dialog.
 *
 * A real `<input type="file">` underneath rather than a div pretending to be one: that is what
 * gives keyboard operation, the OS file picker, and screen-reader support for free. The drop
 * target is an enhancement layered over it, not a replacement for it.
 *
 * The `accept` hint is advisory — a browser file dialog filters on it but a drop does not, and
 * the backend validates the format regardless. So this component does not reject a file for
 * having the wrong extension; it shows what was chosen and lets the server be the authority.
 * Guessing here would mean rejecting a valid `.txt` export of an Nmap run.
 */
export function FileDropzone({
  onSelect,
  accept,
  label,
  hint,
  selected,
  onClear,
  disabled = false,
  className,
}: {
  onSelect: (file: File) => void
  /** Passed to the input. A hint for the OS dialog, not a validation rule. */
  accept?: string
  label: string
  hint?: string
  /** The currently chosen file, so the caller owns the selection. */
  selected?: File | null
  onClear?: () => void
  disabled?: boolean
  className?: string
}) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const describedBy = useId()

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setDragging(false)
    if (disabled) return
    const file = event.dataTransfer.files?.[0]
    if (file) onSelect(file)
  }

  if (selected) {
    return (
      <div
        className={cn(
          'flex items-center gap-3 rounded-lg border border-border-default bg-surface-sunken px-3.5 py-3',
          className,
        )}
      >
        <FileUp className="size-4 shrink-0 text-accent" aria-hidden />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-body-sm font-medium text-text-primary">
            {selected.name}
          </span>
          <span className="text-caption text-text-tertiary" data-numeric>
            {formatBytes(selected.size)}
          </span>
        </span>
        {onClear ? (
          <IconButton
            label="Remove file"
            icon={<X className="size-4" />}
            size="sm"
            onClick={onClear}
            disabled={disabled}
          />
        ) : null}
      </div>
    )
  }

  return (
    <div
      onDragOver={(event) => {
        event.preventDefault()
        if (!disabled) setDragging(true)
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      className={cn(
        'rounded-lg border border-dashed px-4 py-8 text-center transition-colors duration-(--duration-fast)',
        dragging
          ? 'border-accent bg-accent-surface'
          : 'border-border-default bg-surface-sunken',
        disabled && 'opacity-60',
        className,
      )}
    >
      <FileUp className="mx-auto size-6 text-text-tertiary" aria-hidden />
      <p className="mt-3 text-body-sm text-text-secondary">
        Drop a file here, or{' '}
        <button
          type="button"
          disabled={disabled}
          onClick={() => inputRef.current?.click()}
          className="font-medium text-accent underline decoration-accent-border underline-offset-2 transition-colors hover:text-accent-hover disabled:cursor-not-allowed"
        >
          browse
        </button>
      </p>
      {hint ? (
        <p id={describedBy} className="mt-1 text-caption text-text-tertiary">
          {hint}
        </p>
      ) : null}

      <input
        ref={inputRef}
        type="file"
        accept={accept}
        disabled={disabled}
        aria-label={label}
        aria-describedby={hint ? describedBy : undefined}
        className="sr-only"
        onChange={(event) => {
          const file = event.target.files?.[0]
          if (file) onSelect(file)
          // Cleared so choosing the same file twice in a row still fires a change event.
          event.target.value = ''
        }}
      />
    </div>
  )
}

/** Binary units, because that is what a file manager shows for the same file. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`
}
