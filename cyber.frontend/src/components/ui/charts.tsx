'use client'

import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { ReactNode } from 'react'

import { SEVERITY_LABEL, SEVERITY_ORDER } from '@/lib/severity'
import { cn } from '@/lib/utils'
import type { Severity } from '@/types'

/**
 * Chart wrappers on recharts, which was already a dependency and entirely unused.
 *
 * The point of wrapping rather than using recharts directly at each site is that axes,
 * grids, tooltips and colours are decided once. Charts drawn ad hoc across pages end up
 * with different tick densities, different grid opacities and different tooltip shapes,
 * which reads as three products.
 *
 * Charts are used only where a trend or a distribution is genuinely easier to read than a
 * number or a table. A pie chart of five severities is not — that is what `SeverityTally`
 * is for.
 */

const SEVERITY_VAR: Record<Severity, string> = {
  critical: 'var(--severity-critical)',
  high: 'var(--severity-high)',
  medium: 'var(--severity-medium)',
  low: 'var(--severity-low)',
  info: 'var(--severity-info)',
}

const AXIS = {
  stroke: 'var(--border-default)',
  tick: { fill: 'var(--text-tertiary)', fontSize: 11 },
} as const

export function ChartContainer({
  title,
  description,
  actions,
  height = 220,
  children,
  className,
  /** Rendered instead of the chart when there is nothing to plot. */
  empty,
  isEmpty = false,
}: {
  title?: string
  description?: string
  actions?: ReactNode
  height?: number
  children: ReactNode
  className?: string
  empty?: ReactNode
  isEmpty?: boolean
}) {
  return (
    <div className={cn('min-w-0', className)}>
      {title || actions ? (
        <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            {title ? (
              <h3 className="text-heading font-semibold text-text-primary">{title}</h3>
            ) : null}
            {description ? (
              <p className="mt-0.5 text-body-sm text-text-secondary">{description}</p>
            ) : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}

      {isEmpty ? (
        <div
          className="flex items-center justify-center text-body-sm text-text-tertiary"
          style={{ height }}
        >
          {empty ?? 'No data to plot yet.'}
        </div>
      ) : (
        <div style={{ height }}>
          <ResponsiveContainer width="100%" height="100%">
            {children as never}
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}

/** Shared tooltip, so every chart in the app explains itself the same way. */
function ChartTooltip() {
  return (
    <RechartsTooltip
      cursor={{ fill: 'var(--surface-raised-hover)' }}
      contentStyle={{
        backgroundColor: 'var(--surface-overlay)',
        border: '1px solid var(--border-strong)',
        borderRadius: 8,
        boxShadow: 'var(--elevation-2)',
        fontSize: 12,
        padding: '6px 10px',
      }}
      labelStyle={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: 2 }}
      itemStyle={{ color: 'var(--text-secondary)' }}
    />
  )
}

/**
 * Findings by severity.
 *
 * Horizontal bars rather than vertical: the category labels are words of uneven length, and
 * horizontal bars let them sit on one line each instead of being rotated or truncated.
 */
export function SeverityBarChart({
  counts,
  height = 200,
}: {
  counts: Record<Severity, number>
  height?: number
}) {
  const data = SEVERITY_ORDER.map((severity) => ({
    severity,
    label: SEVERITY_LABEL[severity],
    count: counts[severity],
  }))
  const total = data.reduce((sum, row) => sum + row.count, 0)

  return (
    <ChartContainer height={height} isEmpty={total === 0} empty="No findings recorded yet.">
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 12, bottom: 0, left: 0 }}>
        <CartesianGrid horizontal={false} stroke="var(--border-subtle)" />
        <XAxis
          type="number"
          allowDecimals={false}
          stroke={AXIS.stroke}
          tick={AXIS.tick}
          tickLine={false}
        />
        <YAxis
          type="category"
          dataKey="label"
          width={62}
          stroke={AXIS.stroke}
          tick={AXIS.tick}
          tickLine={false}
          axisLine={false}
        />
        <ChartTooltip />
        <Bar dataKey="count" name="Findings" radius={[0, 4, 4, 0]} maxBarSize={22}>
          {data.map((row) => (
            <Cell key={row.severity} fill={SEVERITY_VAR[row.severity]} />
          ))}
        </Bar>
      </BarChart>
    </ChartContainer>
  )
}

/**
 * Findings over time, stacked by severity.
 *
 * The one place a chart genuinely beats a table here: whether exposure is growing or
 * shrinking is a shape, not a number.
 */
export function TrendAreaChart({
  data,
  height = 220,
}: {
  data: readonly { date: string; critical: number; high: number; medium: number; low: number; info: number }[]
  height?: number
}) {
  const hasAny = data.some(
    (row) => row.critical + row.high + row.medium + row.low + row.info > 0,
  )

  return (
    <ChartContainer
      height={height}
      isEmpty={!hasAny}
      empty="Not enough history yet to show a trend."
    >
      <AreaChart data={data as never[]} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
        <CartesianGrid vertical={false} stroke="var(--border-subtle)" />
        <XAxis
          dataKey="date"
          stroke={AXIS.stroke}
          tick={AXIS.tick}
          tickLine={false}
          minTickGap={24}
        />
        <YAxis allowDecimals={false} stroke={AXIS.stroke} tick={AXIS.tick} tickLine={false} />
        <ChartTooltip />
        {/* Stacked most-severe-last so critical sits on top, where the eye lands. */}
        {(['info', 'low', 'medium', 'high', 'critical'] as const).map((severity) => (
          <Area
            key={severity}
            type="monotone"
            dataKey={severity}
            name={SEVERITY_LABEL[severity]}
            stackId="severity"
            stroke={SEVERITY_VAR[severity]}
            fill={SEVERITY_VAR[severity]}
            fillOpacity={0.18}
            strokeWidth={1.5}
          />
        ))}
      </AreaChart>
    </ChartContainer>
  )
}

/**
 * A single proportional bar.
 *
 * Cheaper than a chart for "what is this made of" and it fits inside a card header, which
 * is where that question usually gets asked.
 */
export function DistributionBar({
  counts,
  className,
  label = 'Severity distribution',
}: {
  counts: Record<Severity, number>
  className?: string
  label?: string
}) {
  const total = SEVERITY_ORDER.reduce((sum, severity) => sum + counts[severity], 0)

  if (total === 0) {
    return (
      <div
        className={cn('h-1.5 w-full rounded-full bg-surface-sunken', className)}
        role="img"
        aria-label="No findings"
      />
    )
  }

  const summary = SEVERITY_ORDER.filter((severity) => counts[severity] > 0)
    .map((severity) => `${counts[severity]} ${SEVERITY_LABEL[severity].toLowerCase()}`)
    .join(', ')

  return (
    <div
      className={cn('flex h-1.5 w-full overflow-hidden rounded-full bg-surface-sunken', className)}
      role="img"
      aria-label={`${label}: ${summary}`}
    >
      {SEVERITY_ORDER.map((severity) =>
        counts[severity] > 0 ? (
          <span
            key={severity}
            style={{
              width: `${(counts[severity] / total) * 100}%`,
              backgroundColor: SEVERITY_VAR[severity],
            }}
          />
        ) : null,
      )}
    </div>
  )
}
