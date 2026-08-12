import type { Message, MessageStatus } from '@/types/intake'

/**
 * The four stages a submitted message moves through.
 *
 * The worker commits at each transition, so this reflects real progress rather than a
 * spinner that guesses. On failure it renders `message.error` **verbatim** - that is the
 * payoff of the fail-loudly design: a missing API key or a rate limit shows up here as
 * text an operator can act on, instead of being hidden behind a plausible verdict.
 */

const STAGES: readonly { status: MessageStatus; label: string }[] = [
  { status: 'pending', label: 'Queued' },
  { status: 'parsing', label: 'Parsing' },
  { status: 'analyzing', label: 'Analysing' },
  { status: 'completed', label: 'Done' },
]

function stageIndex(status: MessageStatus): number {
  const found = STAGES.findIndex((stage) => stage.status === status)
  return found === -1 ? 0 : found
}

export default function IntakeProgress({ message }: { message: Message }) {
  const failed = message.status === 'failed'
  const current = stageIndex(message.status)

  return (
    <div className="intake-progress">
      <ol className="intake-stages">
        {STAGES.map((stage, index) => {
          let state = 'todo'
          if (failed && index <= current) state = 'failed'
          else if (index < current) state = 'done'
          else if (index === current) state = 'active'

          return (
            <li key={stage.status} className={`intake-stage ${state}`}>
              <span className="intake-stage-dot" />
              {stage.label}
            </li>
          )
        })}
      </ol>

      {failed && message.error ? (
        <div className="error">
          <strong>Analysis failed.</strong>
          {/* Verbatim, as text. This is the reason an operator needs to see. */}
          <p>{message.error}</p>
        </div>
      ) : null}

      {message.status === 'completed' ? (
        <p className="muted">
          {message.finding_count === 1
            ? '1 finding recorded'
            : `${message.finding_count} findings recorded`}
          {message.link_count > 0 ? ` · ${message.link_count} link(s) examined` : ''}
          {message.attachment_count > 0
            ? ` · ${message.attachment_count} attachment(s) examined`
            : ''}
        </p>
      ) : null}
    </div>
  )
}
