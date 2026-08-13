import { Badge } from '@/components/ui/Badge'
import { Check, CircleDashed, CircleX, Loader2 } from '@/components/ui/icons'
import { InlineError } from '@/components/ui/states'
import { cn } from '@/lib/utils'
import type { IntakeStatus } from '@/types'

/**
 * The four stages any submitted artifact moves through.
 *
 * Shared by scan intake and message intake because they genuinely share a lifecycle: a file
 * arrives, a worker parses it, an agent assesses it, findings land. The worker commits at each
 * transition, so this reflects real progress rather than a spinner that guesses.
 *
 * On failure the error is rendered **verbatim**. That is the payoff of the fail-loudly design
 * throughout this platform: a missing API key or a rate limit shows up here as text an
 * operator can act on, instead of being hidden behind a plausible-looking verdict.
 */

const STAGES: readonly { status: IntakeStatus; label: string; hint: string }[] = [
  { status: 'pending', label: 'Queued', hint: 'Stored and handed to a worker.' },
  { status: 'parsing', label: 'Parsing', hint: 'Structure extracted, nothing judged yet.' },
  { status: 'analyzing', label: 'Analysing', hint: 'Rules run, then the model explains.' },
  { status: 'completed', label: 'Done', hint: 'Findings written.' },
]

function stageIndex(status: IntakeStatus): number {
  const found = STAGES.findIndex((stage) => stage.status === status)
  return found === -1 ? 0 : found
}

export interface IntakeSummaryItem {
  label: string
  value: string | number
}

export function IntakeProgress({
  status,
  error,
  summary,
  className,
}: {
  status: IntakeStatus
  /** Shown verbatim when the status is `failed`. */
  error?: string | null
  /** Counts to show once it finishes — findings, links, hosts. */
  summary?: readonly IntakeSummaryItem[]
  className?: string
}) {
  const failed = status === 'failed'
  const current = stageIndex(status)

  return (
    <div className={cn('space-y-4', className)}>
      <ol className="grid gap-2 sm:grid-cols-4" aria-label="Analysis progress">
        {STAGES.map((stage, index) => {
          const state = failed
            ? index <= current
              ? 'failed'
              : 'todo'
            : index < current
              ? 'done'
              : index === current
                ? 'active'
                : 'todo'

          return (
            <li
              key={stage.status}
              aria-current={state === 'active' ? 'step' : undefined}
              className={cn(
                'rounded-md border px-3 py-2',
                state === 'done' && 'border-status-ok/30 bg-status-ok-bg',
                state === 'active' && 'border-accent-border bg-accent-surface',
                state === 'failed' && 'border-status-error/30 bg-status-error-bg',
                state === 'todo' && 'border-border-subtle bg-surface-sunken',
              )}
            >
              <span className="flex items-center gap-2">
                <StageIcon state={state} />
                <span
                  className={cn(
                    'text-body-sm font-medium',
                    state === 'todo' ? 'text-text-tertiary' : 'text-text-primary',
                  )}
                >
                  {stage.label}
                </span>
              </span>
              <span className="mt-0.5 block text-caption text-text-tertiary">
                {stage.hint}
              </span>
            </li>
          )
        })}
      </ol>

      {/* `aria-live` so a status change is announced without stealing focus. */}
      <p className="sr-only" aria-live="polite">
        {failed ? 'Analysis failed' : `Stage: ${STAGES[current]?.label ?? 'queued'}`}
      </p>

      {failed ? (
        <InlineError error={error || 'The worker did not record a reason.'} />
      ) : null}

      {status === 'completed' && summary && summary.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2">
          {summary.map((item) => (
            <Badge key={item.label} tone="neutral">
              <span data-numeric>{item.value}</span>
              <span className="ml-1 text-text-tertiary">{item.label}</span>
            </Badge>
          ))}
        </div>
      ) : null}
    </div>
  )
}

function StageIcon({ state }: { state: 'done' | 'active' | 'failed' | 'todo' }) {
  const shared = 'size-3.5 shrink-0'
  if (state === 'done') return <Check className={cn(shared, 'text-status-ok')} aria-hidden />
  if (state === 'failed')
    return <CircleX className={cn(shared, 'text-status-error')} aria-hidden />
  if (state === 'active')
    return (
      <Loader2
        className={cn(shared, 'animate-spin text-accent motion-reduce:animate-none')}
        aria-hidden
      />
    )
  return <CircleDashed className={cn(shared, 'text-text-tertiary')} aria-hidden />
}
