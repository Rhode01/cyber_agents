import { Well } from '@/components/ui/Card'
import { Hint } from '@/components/ui/overlays'
import { cn } from '@/lib/utils'
import {
  PRIORITY_FACTOR_LABEL,
  PRIORITY_FACTOR_ORDER,
  PRIORITY_VALUE_HINT,
} from '@/lib/findings'
import type { FindingPriority, PriorityFactor } from '@/types'

/**
 * Every factor that produced a remediation score, and what each contributed.
 *
 * This is the whole reason the score is additive and bounded rather than a single opaque
 * number: an analyst who disagrees with a ranking can see exactly which factor they
 * disagree with. A number nobody can argue with is a number nobody trusts.
 *
 * Factors render in the fixed order the score adds them, with any key the engine sends that
 * this build does not recognise appended rather than dropped — a newer ai.engine must not
 * silently lose a factor here.
 *
 * Retokenised onto the design system from the pre-redesign version; the logic is unchanged.
 */

interface PriorityBreakdownProps {
  priority: FindingPriority
  className?: string
}

export function PriorityBreakdown({ priority, className }: PriorityBreakdownProps) {
  // Resolved into pairs rather than looked up per row: the factor map is indexed by an
  // arbitrary string, so every lookup is `PriorityFactor | undefined`.
  const known = PRIORITY_FACTOR_ORDER.map((key) => [key, priority.factors[key]] as const)
  const unknown = Object.entries(priority.factors)
    .filter(([key]) => !PRIORITY_FACTOR_ORDER.includes(key as never))
    .sort(([a], [b]) => a.localeCompare(b))
  const ordered = [...known, ...unknown].filter(
    (entry): entry is [string, PriorityFactor] => entry[1] !== undefined,
  )

  if (ordered.length === 0) return null

  const percent = Math.min(100, Math.round((priority.score / priority.max_score) * 100))

  return (
    <Well className={cn('p-4', className)}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <span className="text-body-sm font-semibold text-text-primary">
            Remediation priority
          </span>
          <span className="ml-2 text-caption text-text-tertiary">
            rank #<span data-numeric>{priority.rank}</span> in this assessment
          </span>
        </div>
        <span className="font-mono text-body-sm text-accent" data-numeric>
          {Math.round(priority.score)}
          <span className="text-text-tertiary"> / {priority.max_score}</span>
        </span>
      </div>

      <Meter
        percent={percent}
        tone="accent"
        className="mt-2 h-1.5"
        label={`Score ${Math.round(priority.score)} of ${priority.max_score}`}
      />

      <dl className="mt-4 grid gap-2">
        {ordered.map(([key, factor]) => {
          const width =
            factor.max_points > 0
              ? Math.min(100, Math.round((factor.points / factor.max_points) * 100))
              : 0
          const hint = PRIORITY_VALUE_HINT[factor.value]

          return (
            <div
              key={key}
              className="grid grid-cols-[minmax(0,10rem)_1fr_auto] items-center gap-3"
            >
              <dt className="truncate text-label text-text-secondary">
                {PRIORITY_FACTOR_LABEL[key] ?? key}
              </dt>
              <dd className="flex min-w-0 items-center gap-2">
                {hint ? (
                  <Hint content={hint}>
                    <span className="truncate font-mono text-label text-text-primary underline decoration-border-strong decoration-dotted underline-offset-2">
                      {factor.value}
                    </span>
                  </Hint>
                ) : (
                  <span className="truncate font-mono text-label text-text-primary">
                    {factor.value}
                  </span>
                )}
                <Meter percent={width} tone="muted" className="h-1 min-w-8 flex-1" />
              </dd>
              <dd className="font-mono text-caption text-text-tertiary" data-numeric>
                {factor.points}
                <span className="opacity-60">/{factor.max_points}</span>
              </dd>
            </div>
          )
        })}
      </dl>

      <p className="mt-3 text-caption text-text-tertiary">
        Computed deterministically from the factors above. Not model output.
      </p>
    </Well>
  )
}

/**
 * A proportion bar.
 *
 * `role="img"` with a label rather than a `progressbar`: this reports a computed score, not
 * work in progress, and a screen reader announcing "progress 68%" would be wrong about what
 * the number means.
 */
function Meter({
  percent,
  tone,
  className,
  label,
}: {
  percent: number
  tone: 'accent' | 'muted'
  className?: string
  label?: string
}) {
  return (
    <span
      className={cn(
        'block w-full overflow-hidden rounded-full bg-surface-raised',
        className,
      )}
      {...(label ? { role: 'img', 'aria-label': label } : { 'aria-hidden': true })}
    >
      <span
        className={cn(
          'block h-full rounded-full',
          tone === 'accent' ? 'bg-accent' : 'bg-border-strong',
        )}
        style={{ width: `${percent}%` }}
      />
    </span>
  )
}
