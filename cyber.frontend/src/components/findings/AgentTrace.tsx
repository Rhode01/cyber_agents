import { Well } from '@/components/ui/Card'
import { ChevronRight } from '@/components/ui/icons'
import { cn } from '@/lib/utils'
import type { AgentTraceEntry } from '@/types'

/**
 * The tool calls an agent made, and what came back.
 *
 * This is the platform's audit trail: it is how an analyst answers "did the agent actually
 * look, or did it guess?". Worth surfacing rather than leaving in the evidence blob.
 *
 * The pre-redesign version dressed this as a fake macOS terminal window, complete with
 * traffic-light buttons. The skin is gone; the content is not. A monospace log inside a well
 * says "captured output" without pretending to be a shell we do not have.
 *
 * `args` and `result` are untrusted — a tool result can contain a scanned banner or an
 * attacker-authored page — so both are rendered as text.
 */
export function AgentTrace({
  entries,
  className,
}: {
  entries: readonly AgentTraceEntry[]
  className?: string
}) {
  if (entries.length === 0) return null

  return (
    <Well className={cn('max-h-72 overflow-auto px-0 py-0', className)}>
      <ol className="divide-y divide-border-subtle">
        {entries.map((entry, index) => (
          <li key={index} className="px-3 py-2">
            {entry.type === 'tool_call' ? (
              <p className="flex items-start gap-1.5 font-mono text-caption leading-5">
                <ChevronRight
                  className="mt-0.5 size-3 shrink-0 text-accent"
                  aria-hidden
                />
                <span className="min-w-0 break-all">
                  <span className="font-semibold text-accent">{entry.tool ?? 'tool'}</span>
                  {entry.args !== undefined ? (
                    <span className="text-text-tertiary"> {JSON.stringify(entry.args)}</span>
                  ) : null}
                </span>
              </p>
            ) : (
              <pre className="whitespace-pre-wrap break-words pl-4.5 font-mono text-caption leading-5 text-text-secondary">
                {String(entry.result ?? '')}
              </pre>
            )}
          </li>
        ))}
      </ol>
    </Well>
  )
}

/** Read an agent trace off a finding's evidence, defensively. Never throws. */
export function readAgentTrace(evidence: Record<string, unknown> | undefined): AgentTraceEntry[] {
  const raw = evidence?.agent_trace
  if (!Array.isArray(raw)) return []

  const entries: AgentTraceEntry[] = []
  for (const item of raw) {
    if (typeof item !== 'object' || item === null) continue
    const record = item as Record<string, unknown>
    if (record.type !== 'tool_call' && record.type !== 'tool_result') continue
    entries.push({
      type: record.type,
      tool: typeof record.tool === 'string' ? record.tool : undefined,
      args: record.args,
      tool_call_id: typeof record.tool_call_id === 'string' ? record.tool_call_id : undefined,
      result: typeof record.result === 'string' ? record.result : undefined,
    })
  }
  return entries
}
