/**
 * API client for the phishing message intake.
 *
 * Separate from `src/lib/api.ts` for two reasons, one social and one technical.
 *
 * The social one: that file is being actively edited for the vulnerability findings UI,
 * and adding to it would mean a merge conflict over changes that share nothing.
 *
 * The technical one matters more. `api.ts`'s `request` sets
 * `'Content-Type': init?.body ? 'application/json' : undefined`, which breaks multipart
 * uploads: for `FormData` the browser has to set that header itself, because only it
 * knows the boundary token. Forcing `application/json` on a `FormData` body produces a
 * request the server cannot parse. The client below sets a content type only for JSON and
 * leaves `FormData` alone.
 */

import type { Finding, FindingList } from '@/types'
import type { Message, MessageList, MessageStatus, MessageVerdict } from '@/types/intake'

export const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL ?? 'http://localhost:8000'

export class IntakeError extends Error {
  readonly status: number | null

  constructor(message: string, status: number | null = null) {
    super(message)
    this.name = 'IntakeError'
    this.status = status
  }
}

/** FastAPI reports validation failures as `{loc, msg, type}` objects, not strings. */
function formatDetail(detail: unknown): string {
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => (item && typeof item === 'object' && 'msg' in item ? item.msg : item))
      .filter(Boolean)
    if (messages.length > 0) return messages.join('; ')
  }
  try {
    return JSON.stringify(detail)
  } catch {
    return String(detail)
  }
}

async function send<T>(path: string, init?: RequestInit): Promise<T> {
  // A content type is set only for a JSON string body. FormData is left untouched so the
  // browser can supply multipart/form-data with its boundary.
  const headers: Record<string, string> = { accept: 'application/json' }
  if (typeof init?.body === 'string') headers['content-type'] = 'application/json'

  let response: Response
  try {
    response = await fetch(`${BACKEND_URL}${path}`, {
      ...init,
      headers: { ...headers, ...(init?.headers as Record<string, string> | undefined) },
      cache: 'no-store',
    })
  } catch {
    throw new IntakeError(
      `Could not reach the backend at ${BACKEND_URL}. Is it running on port 8000?`,
      null,
    )
  }

  if (!response.ok) {
    let detail = `The backend responded ${response.status} for ${path}`
    try {
      const body = await response.json()
      if (body?.detail) detail = formatDetail(body.detail)
    } catch {
      // Keep the status-code message; a body that will not parse adds nothing.
    }
    throw new IntakeError(detail, response.status)
  }

  return (await response.json()) as T
}

/**
 * Upload an email file for analysis.
 *
 * `enrich` opts in to fetching the linked pages, which is the only thing that contacts
 * the suspect host. Off by default, both here and on the server.
 */
export function uploadMessage(file: File, enrich = false): Promise<Message> {
  const form = new FormData()
  form.append('file', file)
  form.append('enrich', String(enrich))
  return send<Message>('/messages', { method: 'POST', body: form })
}

/** Submit a bare URL or domain for analysis. */
export function submitUrl(url: string, enrich = false): Promise<Message> {
  return send<Message>('/messages/url', {
    method: 'POST',
    body: JSON.stringify({ url, enrich }),
  })
}

/** Fetch one intake record. This is the poll target after a submission. */
export function fetchMessage(id: string): Promise<Message> {
  return send<Message>(`/messages/${id}`)
}

export function fetchMessages(
  options: { status?: MessageStatus; verdict?: MessageVerdict; limit?: number; offset?: number } = {},
): Promise<MessageList> {
  const params = new URLSearchParams()
  if (options.status) params.set('status', options.status)
  if (options.verdict) params.set('verdict', options.verdict)
  params.set('limit', String(options.limit ?? 50))
  params.set('offset', String(options.offset ?? 0))
  return send<MessageList>(`/messages?${params.toString()}`)
}

/** The findings one submitted message produced. */
export function fetchMessageFindings(messageId: string): Promise<FindingList> {
  const params = new URLSearchParams({ message_id: messageId, limit: '50' })
  return send<FindingList>(`/findings?${params.toString()}`)
}

export function fetchFinding(id: string): Promise<Finding> {
  return send<Finding>(`/findings/${id}`)
}
