/**
 * The one place finding *kind* and *priority* presentation is defined.
 *
 * Severity says how bad something is; `finding_type` says what it is, and
 * `evidence.priority` says what to fix first. The last of those is computed
 * deterministically by the ai.engine - never by a model - which is why it is worth
 * showing an analyst as the reason for a ranking rather than hiding it in a JSON
 * blob. See `cyber.ai.engine/app/agents/vulnerability/prioritize.py`.
 *
 * IMPORTANT - two rules inherited from `lib/severity.ts`:
 *
 * 1. Tailwind v4 scans source files for *literal* class strings, so every class
 *    name here is written out in full. An interpolated `bg-finding-${type}` is
 *    invisible to the scanner and generates no CSS at all.
 * 2. `evidence` is untrusted data lifted out of a service banner. Its *values* are
 *    escaped by React, but its *shape* is not guaranteed by anything, so every
 *    reader below is a type guard rather than a cast. A malformed evidence blob
 *    must render as "not available", never throw and blank the page.
 */

import { SEVERITY_WEIGHT } from '@/lib/severity'
import type {
  Finding,
  FindingPriority,
  FindingStatus,
  FindingType,
  PriorityFactor,
  Severity,
  VerificationEntry,
  VerificationOutcome,
} from '@/types'

/** Reading order for a findings list: what it is, before how bad it is. */
export const FINDING_TYPE_ORDER = [
  'known_cve',
  'risky_exposed_service',
  'outdated_service',
  'weak_configuration',
  'phishing_message',
  'malicious_url',
  'prompt_injection_attempt',
  'informational',
] as const satisfies readonly FindingType[]

export const FINDING_TYPE_LABEL: Record<FindingType, string> = {
  known_cve: 'Known CVE',
  risky_exposed_service: 'Risky exposure',
  outdated_service: 'Outdated service',
  weak_configuration: 'Weak config',
  phishing_message: 'Phishing message',
  malicious_url: 'Malicious URL',
  prompt_injection_attempt: 'Injection attempt',
  informational: 'Informational',
}

/** One line an analyst can read to know why the kind matters. */
export const FINDING_TYPE_HINT: Record<FindingType, string> = {
  known_cve: 'The installed version falls inside a documented affected range.',
  risky_exposed_service: 'Reaching this service is the finding, whatever version it runs.',
  outdated_service: 'Running below the minimum supported version.',
  weak_configuration: 'Configured in a way that weakens an otherwise current service.',
  phishing_message:
    'One submitted message, assessed as a whole. The indicators behind the verdict are in the evidence.',
  malicious_url: 'One submitted link or domain, assessed on its structure and destination.',
  prompt_injection_attempt:
    'The ingested content contained text addressed to an automated analyst. It was fenced and never followed.',
  informational: 'No rule matched. A statement about the rules, not a clean bill of health.',
}

/**
 * Kind chips stay monochrome so they do not compete with the severity badge beside them -
 * the label already distinguishes them. The one exception is an injection attempt, which is
 * a security event about the pipeline itself and earns the alarm colour.
 */
const NEUTRAL_CHIP = 'text-text-tertiary bg-surface-sunken border-border-default'

export const FINDING_TYPE_CLASS: Record<FindingType, string> = {
  known_cve: NEUTRAL_CHIP,
  risky_exposed_service: NEUTRAL_CHIP,
  outdated_service: NEUTRAL_CHIP,
  weak_configuration: NEUTRAL_CHIP,
  phishing_message: NEUTRAL_CHIP,
  malicious_url: NEUTRAL_CHIP,
  prompt_injection_attempt:
    'text-severity-critical bg-severity-critical-bg border-severity-critical/30',
  informational: NEUTRAL_CHIP,
}

/** Human label for a priority factor key, in the order the score adds them up. */
export const PRIORITY_FACTOR_LABEL: Record<string, string> = {
  severity: 'Severity',
  internet_exposure: 'Internet exposure',
  exploit_availability: 'Exploit availability',
  authentication_required: 'Authentication required',
  business_criticality: 'Business criticality',
  asset_type: 'Asset type',
}

export const PRIORITY_FACTOR_ORDER = [
  'severity',
  'internet_exposure',
  'exploit_availability',
  'authentication_required',
  'business_criticality',
  'asset_type',
] as const

/** Why a factor scored what it did, where the value alone is not obvious. */
export const PRIORITY_VALUE_HINT: Record<string, string> = {
  unknown: 'Could not be established. Scored above the safe answer, not below it.',
  internet: 'A globally-routable address.',
  internal: 'Private, loopback or link-local. Not routable from the internet.',
  'known-exploited': 'Exploitation has been observed in the wild.',
  none: 'No credentials stand in the way of reaching this.',
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function readFactor(value: unknown): PriorityFactor | null {
  if (!isRecord(value)) return null
  const { points, max_points: maxPoints } = value
  if (typeof points !== 'number' || typeof maxPoints !== 'number') return null
  return { value: String(value.value ?? 'unknown'), points, max_points: maxPoints }
}

/**
 * Pull the priority block off a finding's evidence, or null when it has none.
 *
 * Findings from the three agents without a rule engine carry no priority at all,
 * so absence is normal rather than an error.
 */
export function readPriority(finding: Finding): FindingPriority | null {
  const raw = finding.evidence?.priority
  if (!isRecord(raw)) return null

  const { score, rank, max_score: maxScore } = raw
  if (typeof score !== 'number' || typeof rank !== 'number') return null

  const factors: Record<string, PriorityFactor> = {}
  if (isRecord(raw.factors)) {
    for (const [key, value] of Object.entries(raw.factors)) {
      const factor = readFactor(value)
      if (factor) factors[key] = factor
    }
  }

  return {
    score,
    rank,
    max_score: typeof maxScore === 'number' && maxScore > 0 ? maxScore : 100,
    factors,
  }
}

export interface AssetRisk {
  asset: string
  finding_count: number
  top_score: number
  total_score: number
  worst_severity: Severity
  severities: Record<string, number>
}

const SEVERITIES = new Set<string>(['critical', 'high', 'medium', 'low', 'info'])

function readAssetRisk(value: unknown): AssetRisk | null {
  if (!isRecord(value)) return null
  const { asset, finding_count: count, top_score: top, total_score: total } = value
  if (typeof asset !== 'string' || typeof count !== 'number' || typeof top !== 'number') return null
  const worst = value.worst_severity
  if (typeof worst !== 'string' || !SEVERITIES.has(worst)) return null

  const severities: Record<string, number> = {}
  if (isRecord(value.severities)) {
    for (const [key, tally] of Object.entries(value.severities)) {
      if (typeof tally === 'number') severities[key] = tally
    }
  }

  return {
    asset,
    finding_count: count,
    top_score: top,
    total_score: typeof total === 'number' ? total : top,
    worst_severity: worst as Severity,
    severities,
  }
}

/**
 * The per-asset risk ranking, answering "which assets are most riskiest first".
 *
 * Every finding from one assessment carries the same ranking, so this reads it
 * off whichever finding has the most complete copy rather than recomputing it -
 * the ai.engine ranks on the single worst finding per asset, and duplicating that
 * rule here is how the two would drift apart.
 */
export function readAssetRanking(findings: readonly Finding[]): AssetRisk[] {
  let best: AssetRisk[] = []
  for (const finding of findings) {
    const raw = finding.evidence?.asset_risk_ranking
    if (!Array.isArray(raw)) continue
    const parsed = raw.map(readAssetRisk).filter((risk): risk is AssetRisk => risk !== null)
    if (parsed.length > best.length) best = parsed
  }
  return best
}

/** Whether a finding came from the rule engine alone, with no model write-up. */
export function isRulesOnly(finding: Finding): boolean {
  const assessment = finding.evidence?.assessment
  return isRecord(assessment) && assessment.assessed_by === 'rules-only'
}

const VERIFICATION_OUTCOMES = new Set<string>([
  'resolved',
  'still_present',
  'unverified',
  'unverifiable',
])

/** Statuses that still need an analyst's attention. */
export const OPEN_STATUSES: readonly FindingStatus[] = ['new', 'triaged']

export const STATUS_LABEL: Record<FindingStatus, string> = {
  new: 'Open',
  triaged: 'Triaged',
  resolved: 'Resolved',
  false_positive: 'Dismissed',
}

export const STATUS_CLASS: Record<FindingStatus, string> = {
  new: 'text-text-secondary bg-surface-sunken border-border-default',
  triaged: 'text-status-active bg-status-active-bg border-status-active/25',
  resolved: 'text-status-ok bg-status-ok-bg border-status-ok/25',
  // Dismissed recedes furthest: it is a decision already taken, and it should not draw the
  // eye the way an open finding does.
  false_positive: 'text-text-tertiary bg-surface-sunken border-border-subtle',
}

export const VERIFICATION_LABEL: Record<VerificationOutcome, string> = {
  resolved: 'Confirmed fixed',
  still_present: 'Still present',
  unverified: 'Could not verify',
  unverifiable: 'Cannot be verified',
}

/** Could-not-verify is deliberately warning-coloured rather than neutral.
 *  An inconclusive re-check that looks like a clean one is the failure mode the
 *  whole verification design exists to prevent, so it must not read as reassuring. */
export const VERIFICATION_CLASS: Record<VerificationOutcome, string> = {
  resolved: 'text-status-ok',
  still_present: 'text-severity-medium',
  unverified: 'text-severity-high',
  unverifiable: 'text-text-tertiary',
}

/** The verification history on a finding, oldest first. Empty when never checked. */
export function readVerification(finding: Finding): VerificationEntry[] {
  const raw = finding.evidence?.verification
  if (!Array.isArray(raw)) return []

  const entries: VerificationEntry[] = []
  for (const item of raw) {
    if (!isRecord(item)) continue
    const { outcome, reason, verified_at: verifiedAt } = item
    if (typeof outcome !== 'string' || !VERIFICATION_OUTCOMES.has(outcome)) continue
    entries.push({
      outcome: outcome as VerificationOutcome,
      reason: typeof reason === 'string' ? reason : '',
      verified_at: typeof verifiedAt === 'string' ? verifiedAt : '',
      recorded_at: typeof item.recorded_at === 'string' ? item.recorded_at : '',
      source: typeof item.source === 'string' ? item.source : '',
    })
  }
  return entries
}

/** The most recent verification attempt, or null. */
export function latestVerification(finding: Finding): VerificationEntry | null {
  const entries = readVerification(finding)
  return entries.length > 0 ? entries[entries.length - 1]! : null
}

/**
 * Sort comparator: most urgent remediation first.
 *
 * Priority rank wins where both findings have one. Anything without a priority
 * sorts after everything that has one, then by severity, so the three agents
 * without a rule engine do not interleave into the middle of the queue.
 */
export function byPriority(severityWeight: Record<Severity, number>) {
  return (a: Finding, b: Finding): number => {
    const left = readPriority(a)
    const right = readPriority(b)
    if (left && right) return right.score - left.score || left.rank - right.rank
    if (left) return -1
    if (right) return 1
    return severityWeight[b.severity] - severityWeight[a.severity]
  }
}

/**
 * Sort comparator: most severe finding first.
 *
 * A thin adapter over `bySeverityDesc`, which compares bare severities. Having it here means
 * call sites read `.sort(bySeverity)` rather than repeating the property access, and there is
 * one place to change if ties ever need a secondary key.
 */
export function bySeverity(a: Finding, b: Finding): number {
  return SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity]
}

/** `10.0.0.5:22/tcp`, or just the asset when there is no port. */
export function formatLocation(finding: Finding): string {
  const asset = finding.asset ?? 'No asset'
  if (finding.port === null || finding.port === undefined) return asset
  const protocol = finding.protocol ? `/${finding.protocol}` : ''
  return `${asset}:${finding.port}${protocol}`
}
