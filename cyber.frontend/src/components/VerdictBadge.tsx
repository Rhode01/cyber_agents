import type { MessageVerdict } from '@/types/intake'

/**
 * The headline answer for one submitted message.
 *
 * `null` renders as "no verdict" rather than as anything reassuring. That distinction is
 * load-bearing: a failed analysis leaves the verdict null, and showing it the same way as
 * `clean` would let an operator read a failure as a clean bill of health.
 */
export default function VerdictBadge({
  verdict,
  status,
}: {
  verdict: MessageVerdict | null
  status?: string
}) {
  if (verdict === null) {
    const pending = status === 'pending' || status === 'parsing' || status === 'analyzing'
    return (
      <span className={pending ? 'pill pending' : 'pill bad'}>
        <span className={pending ? 'dot warn' : 'dot bad'} />
        {pending ? 'Analysing…' : 'No verdict'}
      </span>
    )
  }

  const style: Record<MessageVerdict, { className: string; dot: string; label: string }> = {
    phishing: { className: 'pill bad', dot: 'dot bad', label: 'Phishing' },
    suspicious: { className: 'pill pending', dot: 'dot warn', label: 'Suspicious' },
    clean: { className: 'pill ok', dot: 'dot ok', label: 'Clean' },
  }
  const chosen = style[verdict]

  return (
    <span className={chosen.className}>
      <span className={chosen.dot} />
      {chosen.label}
    </span>
  )
}
