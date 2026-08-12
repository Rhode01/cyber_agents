/**
 * Types for the phishing message intake.
 *
 * Kept separate from `src/types/index.ts` deliberately, not accidentally: that file is
 * being actively edited for the vulnerability findings UI, and splitting avoids a merge
 * conflict over a file neither change really shares. Fold these in whenever that work
 * settles.
 */

/** How an artifact arrived. */
export type MessageFormat = 'email_mime' | 'url'

/** Lifecycle of one submitted message. The worker advances it. */
export type MessageStatus = 'pending' | 'parsing' | 'analyzing' | 'completed' | 'failed'

/** The headline answer, denormalised onto the intake row by the worker. */
export type MessageVerdict = 'clean' | 'suspicious' | 'phishing'

/** Statuses after which polling should stop. */
export const TERMINAL_STATUSES: readonly MessageStatus[] = ['completed', 'failed']

export interface Message {
  id: string
  filename: string
  format: MessageFormat
  size_bytes: number
  sha256: string
  submitted_url: string | null
  /** UNTRUSTED - whatever the sender wrote. Render as text, never as markup. */
  sender: string | null
  /** UNTRUSTED. Render as text, never as markup. */
  subject: string | null
  status: MessageStatus
  job_id: string | null
  link_count: number
  attachment_count: number
  finding_count: number
  /**
   * `null` while pending, and after a failure.
   *
   * Deliberately different from `'clean'`: null means "no verdict was reached", clean
   * means "analysed and nothing found". Showing them the same way would let a failed
   * analysis read as a clean bill of health.
   */
  verdict: MessageVerdict | null
  /** Why this message produced no verdict. Shown verbatim. */
  error: string | null
  created_at: string
  updated_at: string
  completed_at: string | null
}

export interface MessageList {
  items: Message[]
  total: number
  limit: number
  offset: number
}

/** Which rule family produced an indicator. */
export type IndicatorCategory =
  | 'authentication'
  | 'identity'
  | 'url'
  | 'content'
  | 'attachment'
  | 'injection'

/**
 * One deterministic indicator, as stored in `Finding.evidence.indicators`.
 *
 * `fact`, `locus` and `evidence` embed attacker-authored strings. Render every one of
 * them as text. `dangerouslySetInnerHTML` must not appear anywhere near this type.
 */
export interface Indicator {
  indicator_id: string
  rule_id: string
  category: IndicatorCategory
  /** Where it was found - `header:From`, `link:2`, `attachment:invoice.pdf.exe`. UNTRUSTED. */
  locus: string
  /** A deterministic sentence embedding untrusted values. UNTRUSTED. */
  fact: string
  weight: number
  severity_floor: string
  /** Why the rule exists. Written by us, so safe to show as guidance. */
  rationale: string
  evidence: Record<string, unknown>
}

/** Human-readable labels for the six categories. */
export const CATEGORY_LABEL: Record<IndicatorCategory, string> = {
  authentication: 'Sender authentication',
  identity: 'Sender identity',
  url: 'Links',
  content: 'Message content',
  attachment: 'Attachments',
  injection: 'Aimed at the analyser',
}

/**
 * Display order, strongest evidence first.
 *
 * Mirrors the backend's own weighting: authentication and identity are the hardest
 * signals to fake, wording is the easiest.
 */
export const CATEGORY_ORDER: readonly IndicatorCategory[] = [
  'authentication',
  'identity',
  'attachment',
  'url',
  'injection',
  'content',
]
