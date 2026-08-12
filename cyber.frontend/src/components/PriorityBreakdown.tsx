import { cn } from '@/lib/utils'
import {
  PRIORITY_FACTOR_LABEL,
  PRIORITY_FACTOR_ORDER,
  PRIORITY_VALUE_HINT,
} from '@/lib/findings'
import type { FindingPriority, PriorityFactor } from '@/types'

interface PriorityRankProps {
  priority: FindingPriority
  className?: string
}

/**
 * The compact rank pill for a findings list: `#1 · 68`.
 *
 * Rank is per-assessment, so it is only meaningful within one scan - which is why
 * the score travels with it rather than the rank standing alone.
 */
export function PriorityRank({ priority, className }: PriorityRankProps) {
  return (
    <span
      className={cn(
        'inline-flex items-baseline gap-1.5 rounded-md border border-border-strong bg-white/5 px-2 py-0.5 font-mono text-[0.7rem] whitespace-nowrap',
        className,
      )}
      aria-label={`Remediation priority rank ${priority.rank}, score ${priority.score} of ${priority.max_score}`}
    >
      <span className="font-semibold text-accent">#{priority.rank}</span>
      <span className="text-faint">·</span>
      <span className="tabular-nums text-muted">{Math.round(priority.score)}</span>
    </span>
  )
}

interface PriorityBreakdownProps {
  priority: FindingPriority
  className?: string
}

/**
 * Every factor that produced a remediation score, and what each contributed.
 *
 * This is the whole reason the score is additive and bounded rather than a single
 * opaque number: an analyst who disagrees with a ranking can see exactly which
 * factor they disagree with. A number nobody can argue with is a number nobody
 * trusts.
 *
 * Factors are rendered in the fixed order the score adds them, with any key the
 * engine sends that this build does not recognise appended rather than dropped -
 * a newer ai.engine must not silently lose a factor here.
 */
export function PriorityBreakdown({ priority, className }: PriorityBreakdownProps) {
  // Resolved into pairs rather than looked up per row: the factor map is indexed
  // by an arbitrary string, so every lookup is `PriorityFactor | undefined`.
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
    <div className={cn('rounded-[10px] border border-border bg-bg-elev p-4', className)}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <span className="text-sm font-semibold text-text">Remediation priority</span>
          <span className="ml-2 text-xs text-faint">
            rank #{priority.rank} in this assessment
          </span>
        </div>
        <span className="font-mono text-sm tabular-nums text-accent">
          {Math.round(priority.score)}
          <span className="text-faint"> / {priority.max_score}</span>
        </span>
      </div>

      <div
        className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-white/5"
        role="img"
        aria-label={`Score ${Math.round(priority.score)} of ${priority.max_score}`}
      >
        <div className="h-full rounded-full bg-accent" style={{ width: `${percent}%` }} />
      </div>

      <dl className="mt-4 grid gap-2">
        {ordered.map(([key, factor]) => {
          const width =
            factor.max_points > 0
              ? Math.min(100, Math.round((factor.points / factor.max_points) * 100))
              : 0
          const hint = PRIORITY_VALUE_HINT[factor.value]

          return (
            <div key={key} className="grid grid-cols-[minmax(0,11rem)_1fr_auto] items-center gap-3">
              <dt className="truncate text-xs text-muted" title={PRIORITY_FACTOR_LABEL[key] ?? key}>
                {PRIORITY_FACTOR_LABEL[key] ?? key}
              </dt>
              <dd className="flex min-w-0 items-center gap-2">
                <span
                  className="truncate font-mono text-xs text-text"
                  title={hint ? `${factor.value} — ${hint}` : factor.value}
                >
                  {factor.value}
                </span>
                <span className="h-1 min-w-8 flex-1 overflow-hidden rounded-full bg-white/5">
                  <span
                    className="block h-full rounded-full bg-accent-2"
                    style={{ width: `${width}%` }}
                  />
                </span>
              </dd>
              <dd className="font-mono text-[0.7rem] tabular-nums text-faint">
                {factor.points}
                <span className="opacity-60">/{factor.max_points}</span>
              </dd>
            </div>
          )
        })}
      </dl>

      <p className="mt-3 mb-0 text-[0.7rem] text-faint">
        Computed deterministically from the factors above. Not model output.
      </p>
    </div>
  )
}
