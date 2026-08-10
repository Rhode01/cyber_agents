/**
 * The one place severity presentation is defined.
 *
 * Before this file the same five severities were described in four different
 * places with three conflicting colour systems - `info` rendered magenta on
 * Scans, grey on Findings and Reports, and indigo on the badge border. Colours
 * now live only in `globals.css`, exposed to Tailwind through the `@theme inline`
 * block, and this module maps a severity onto those tokens.
 *
 * IMPORTANT - Tailwind v4 scans source files for *literal* class strings. That
 * is why every class name below is written out in full rather than built as
 * `bg-severity-${severity}`: an interpolated name is invisible to the scanner
 * and would generate no CSS at all. The old code got away with
 * `` `sev-${severity}` `` only because those were hand-written CSS rules.
 */

import type { Severity } from '@/types'

/** Most urgent first. Use this anywhere severities are listed or sorted. */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const satisfies readonly Severity[]

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

/**
 * Ranking weight. Mirrors `SEVERITY_ORDER` in the shared contracts package
 * (`cyber.contracts/cyber_contracts/finding.py`) so the frontend and backend
 * agree on what "worse" means.
 */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

interface SeverityClasses {
  /** Foreground, for the label and the dot. */
  readonly text: string
  /** Tinted fill behind the pill. */
  readonly bg: string
  /** Hairline border, same hue as the text. */
  readonly border: string
  /** Solid fill, for bars, pips and swatches. */
  readonly fill: string
}

export const SEVERITY_CLASS: Record<Severity, SeverityClasses> = {
  critical: {
    text: 'text-severity-critical',
    bg: 'bg-severity-critical-bg',
    border: 'border-severity-critical/30',
    fill: 'bg-severity-critical',
  },
  high: {
    text: 'text-severity-high',
    bg: 'bg-severity-high-bg',
    border: 'border-severity-high/30',
    fill: 'bg-severity-high',
  },
  medium: {
    text: 'text-severity-medium',
    bg: 'bg-severity-medium-bg',
    border: 'border-severity-medium/30',
    fill: 'bg-severity-medium',
  },
  low: {
    text: 'text-severity-low',
    bg: 'bg-severity-low-bg',
    border: 'border-severity-low/30',
    fill: 'bg-severity-low',
  },
  info: {
    text: 'text-severity-info',
    bg: 'bg-severity-info-bg',
    border: 'border-severity-info/30',
    fill: 'bg-severity-info',
  },
}

/** Sort comparator: most severe first, for `Array.prototype.sort`. */
export function bySeverityDesc(a: Severity, b: Severity): number {
  return SEVERITY_WEIGHT[b] - SEVERITY_WEIGHT[a]
}

/** Zeroed tally, so callers do not re-declare the shape on every page. */
export function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
}
