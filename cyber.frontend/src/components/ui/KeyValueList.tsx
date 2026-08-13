import type { ReactNode } from 'react'

import { Eyebrow } from '@/components/ui/PageHeader'
import { cn } from '@/lib/utils'

/**
 * Labelled facts about one record.
 *
 * A real `<dl>` rather than a grid of divs, because "asset", "confidence" and "detected" are
 * genuinely term/description pairs and a screen reader should be able to say so. Every page
 * that shows metadata about a finding, a scan or a message uses this, so the label size,
 * colour and spacing cannot drift between them.
 *
 * Values are frequently untrusted — a service banner, a sender address, a subject line — and
 * are rendered as text. Nothing here accepts markup.
 */

export interface KeyValueItem {
  label: string
  /** Rendered as text when a string. A node is for badges and links, never raw HTML. */
  value: ReactNode
  icon?: ReactNode
  /** Monospace the value. For hosts, hashes, ids and anything the eye scans character by character. */
  mono?: boolean
  /** Skipped entirely when false, so callers can express optional rows inline. */
  when?: boolean
}

export function KeyValueList({
  items,
  columns = 2,
  className,
}: {
  items: readonly KeyValueItem[]
  columns?: 1 | 2 | 3
  className?: string
}) {
  const shown = items.filter((item) => item.when !== false)
  if (shown.length === 0) return null

  return (
    <dl
      className={cn(
        'grid gap-x-6 gap-y-3.5',
        columns === 1 && 'grid-cols-1',
        columns === 2 && 'sm:grid-cols-2',
        columns === 3 && 'sm:grid-cols-2 lg:grid-cols-3',
        className,
      )}
    >
      {shown.map((item) => (
        <div key={item.label} className="min-w-0">
          <dt>
            <Eyebrow>
              <span className="inline-flex items-center gap-1.5">
                {item.icon ? <span aria-hidden>{item.icon}</span> : null}
                {item.label}
              </span>
            </Eyebrow>
          </dt>
          <dd
            className={cn(
              'mt-1 break-words text-body-sm text-text-primary',
              item.mono && 'font-mono text-caption',
            )}
          >
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}
