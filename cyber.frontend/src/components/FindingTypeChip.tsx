import { cn } from '@/lib/utils'
import { FINDING_TYPE_CLASS, FINDING_TYPE_HINT, FINDING_TYPE_LABEL } from '@/lib/findings'
import type { FindingType } from '@/types'

interface FindingTypeChipProps {
  type: FindingType
  className?: string
}

/**
 * What kind of problem a finding describes, beside the severity badge.
 *
 * Severity and kind are orthogonal - a risky exposed service can be anything from
 * info to critical - so before this existed an "outdated OpenSSH" and a
 * "prompt-injection attempt" were indistinguishable in a list until you opened
 * them.
 *
 * The accessible name spells out "finding type", because "Known CVE" read out on
 * its own next to "Medium severity" gives no clue which axis it describes.
 */
export function FindingTypeChip({ type, className }: FindingTypeChipProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-2 py-0.5 text-[0.65rem] font-semibold tracking-wide whitespace-nowrap',
        FINDING_TYPE_CLASS[type],
        className,
      )}
      title={FINDING_TYPE_HINT[type]}
      aria-label={`${FINDING_TYPE_LABEL[type]} finding type`}
    >
      {FINDING_TYPE_LABEL[type]}
    </span>
  )
}

interface CveListProps {
  cveIds: readonly string[]
  className?: string
}

/**
 * The CVE identifiers a finding correlates to.
 *
 * These only ever come from the rule engine's version-range matching or from a
 * scanner that asserted them - the contract rejects anything that is not
 * `CVE-YYYY-NNNN`, and a model can never put one here. That is worth surfacing as
 * a real field rather than leaving buried in the evidence blob, because an analyst
 * reads a CVE id as fact.
 */
export function CveList({ cveIds, className }: CveListProps) {
  if (cveIds.length === 0) return null

  return (
    <span className={cn('inline-flex flex-wrap items-center gap-1.5', className)}>
      {cveIds.map((cve) => (
        <a
          key={cve}
          href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`}
          target="_blank"
          rel="noreferrer noopener"
          className="rounded border border-accent/30 bg-accent/10 px-1.5 py-0.5 font-mono text-[0.7rem] text-accent no-underline hover:border-accent/60"
          onClick={(event) => event.stopPropagation()}
        >
          {cve}
        </a>
      ))}
    </span>
  )
}
