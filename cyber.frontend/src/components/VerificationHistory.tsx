import { cn } from '@/lib/utils'
import {
  STATUS_CLASS,
  STATUS_LABEL,
  VERIFICATION_CLASS,
  VERIFICATION_LABEL,
} from '@/lib/findings'
import type { FindingStatus, VerificationEntry } from '@/types'

interface StatusChipProps {
  status: FindingStatus
  className?: string
}

/**
 * A finding's triage state.
 *
 * Nothing displayed this before, so a resolved finding was indistinguishable from
 * an open one in the list - which made the verification loop invisible even when
 * it was working.
 */
export function StatusChip({ status, className }: StatusChipProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-2 py-0.5 text-[0.65rem] font-semibold tracking-wide whitespace-nowrap',
        STATUS_CLASS[status],
        className,
      )}
      aria-label={`Status: ${STATUS_LABEL[status]}`}
    >
      {STATUS_LABEL[status]}
    </span>
  )
}

interface VerificationHistoryProps {
  entries: VerificationEntry[]
  className?: string
}

/**
 * Every attempt to confirm whether this finding is fixed, oldest first.
 *
 * "Could not verify" is rendered as prominently as "Confirmed fixed", and in a
 * warning colour. That is the point of showing this at all: an inconclusive
 * re-check that looks like a clean one is exactly the false confidence the
 * verification design exists to prevent, and hiding it in a JSON blob would
 * reintroduce it at the last step.
 */
export function VerificationHistory({ entries, className }: VerificationHistoryProps) {
  if (entries.length === 0) {
    return (
      <p className={cn('text-sm text-faint', className)}>
        Never re-checked. Use Re-check after applying a fix to confirm it landed.
      </p>
    )
  }

  return (
    <ol className={cn('m-0 grid list-none gap-2 p-0', className)}>
      {entries.map((entry, index) => (
        <li
          key={`${entry.recorded_at}-${index}`}
          className="rounded-[10px] border border-border bg-bg-elev px-4 py-3"
        >
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <span className={cn('text-sm font-semibold', VERIFICATION_CLASS[entry.outcome])}>
              {VERIFICATION_LABEL[entry.outcome]}
            </span>
            {entry.verified_at && (
              <time className="font-mono text-xs text-faint" dateTime={entry.verified_at}>
                {new Date(entry.verified_at).toLocaleString()}
              </time>
            )}
          </div>
          <p className="mt-1 mb-0 text-sm text-muted">{entry.reason}</p>
          {entry.source && (
            <p className="mt-1 mb-0 font-mono text-[0.7rem] text-faint">{entry.source}</p>
          )}
        </li>
      ))}
    </ol>
  )
}
