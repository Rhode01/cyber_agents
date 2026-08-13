import { CircleCheck, CircleHelp, ShieldAlert, TriangleAlert } from '@/components/ui/icons'
import { EmptyState } from '@/components/ui/states'
import { cn } from '@/lib/utils'
import { VERIFICATION_CLASS, VERIFICATION_LABEL } from '@/lib/findings'
import type { VerificationEntry, VerificationOutcome } from '@/types'

/**
 * Every attempt to confirm whether this finding is fixed, oldest first.
 *
 * "Could not verify" is rendered as prominently as "Confirmed fixed", and in a warning
 * colour. That is the point of showing this at all: an inconclusive re-check that looks like
 * a clean one is exactly the false confidence the verification design exists to prevent, and
 * hiding it in a JSON blob would reintroduce it at the last step.
 *
 * Presented as a timeline rather than a list of cards, because the sequence is the
 * information — "still present, still present, resolved" is a different story from
 * "resolved" alone.
 */

const OUTCOME_ICON: Record<VerificationOutcome, typeof CircleCheck> = {
  resolved: CircleCheck,
  still_present: TriangleAlert,
  unverified: ShieldAlert,
  unverifiable: CircleHelp,
}

export function VerificationHistory({
  entries,
  className,
}: {
  entries: readonly VerificationEntry[]
  className?: string
}) {
  if (entries.length === 0) {
    return (
      <EmptyState
        icon={<CircleHelp className="size-5" />}
        title="Never re-checked"
        description="Re-check after applying a fix to confirm it landed. A finding nobody re-checked is still open, whatever was done to it."
        className={className}
      />
    )
  }

  return (
    <ol className={cn('relative ml-2 space-y-4 border-l border-border-subtle pl-5', className)}>
      {entries.map((entry, index) => {
        const Icon = OUTCOME_ICON[entry.outcome]
        return (
          <li key={`${entry.recorded_at}-${index}`} className="relative">
            {/* The node sits on the rail, so `-left-[1.8125rem]` is the rail offset (pl-5 =
                1.25rem) plus half the node's own width. Centring it any other way drifts
                whenever the padding changes. */}
            <span
              aria-hidden
              className={cn(
                'absolute -left-[1.8125rem] top-0.5 grid size-5 place-items-center rounded-full',
                'border border-border-default bg-surface-page',
                VERIFICATION_CLASS[entry.outcome],
              )}
            >
              <Icon className="size-3" />
            </span>

            <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
              <span
                className={cn(
                  'text-body-sm font-semibold',
                  VERIFICATION_CLASS[entry.outcome],
                )}
              >
                {VERIFICATION_LABEL[entry.outcome]}
              </span>
              {entry.verified_at ? (
                <time
                  className="font-mono text-caption text-text-tertiary"
                  dateTime={entry.verified_at}
                  data-numeric
                >
                  {new Date(entry.verified_at).toLocaleString()}
                </time>
              ) : null}
            </div>

            {entry.reason ? (
              <p className="mt-1 text-body-sm text-text-secondary">{entry.reason}</p>
            ) : null}
            {entry.source ? (
              <p className="mt-1 font-mono text-caption text-text-tertiary">{entry.source}</p>
            ) : null}
          </li>
        )
      })}
    </ol>
  )
}
