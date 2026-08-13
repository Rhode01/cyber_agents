import { Badge, Dot } from '@/components/ui/Badge'
import { CircleHelp, MailWarning, ShieldAlert, ShieldCheck } from '@/components/ui/icons'
import type { MessageStatus, MessageVerdict } from '@/types'

/**
 * The headline answer about one submitted message.
 *
 * The distinction this component exists to protect: **no verdict is not a clean verdict.**
 * `verdict === null` on a finished message means the analysis failed and nothing was concluded.
 * Rendering that the same way as `clean` would let a crashed worker read as a clean bill of
 * health, which is the single worst failure mode this platform has.
 *
 * So a failed message gets the alarm treatment, an in-flight one gets a neutral "analysing",
 * and only an actual `clean` verdict is allowed to look reassuring.
 */

const VERDICT = {
  clean: { tone: 'ok', label: 'Clean', Icon: ShieldCheck },
  suspicious: { tone: 'warn', label: 'Suspicious', Icon: ShieldAlert },
  phishing: { tone: 'error', label: 'Phishing', Icon: MailWarning },
} as const

export function VerdictBadge({
  verdict,
  status,
  size = 'md',
}: {
  verdict: MessageVerdict | null
  status: MessageStatus
  size?: 'sm' | 'md'
}) {
  if (verdict !== null) {
    const { tone, label, Icon } = VERDICT[verdict]
    return (
      <Badge tone={tone} size={size} icon={<Icon className="size-3.5" />}>
        {label}
      </Badge>
    )
  }

  if (status === 'failed') {
    return (
      <Badge tone="error" size={size} icon={<CircleHelp className="size-3.5" />}>
        No verdict
      </Badge>
    )
  }

  return (
    <Badge tone="active" size={size} icon={<Dot tone="active" pulse />}>
      Analysing
    </Badge>
  )
}
