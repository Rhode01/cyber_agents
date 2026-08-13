/**
 * Backend API client.
 *
 * NEXT_PUBLIC_BACKEND_URL is read by the browser, so it must be a URL the
 * browser can reach - localhost:8000, not the compose service name.
 */

import type {
  AgentKind,
  AgentRunRequest,
  AgentRunResponse,
  BackendHealth,
  DiscoveryReport,
  Finding,
  FindingList,
  FindingStatus,
  FindingSummary,
  FindingVerifyResponse,
  Message,
  MessageList,
  MessageStatus,
  MessageVerdict,
  RunCreate,
  RunList,
  RunRead,
  RunUpdate,
  Scan,
  ScanIntakeStatus,
  ScanList,
  ScanStatus,
  SystemModules,
} from '@/types'

export const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL ?? 'http://localhost:8000'

export class ApiError extends Error {
  readonly status: number | null

  constructor(message: string, status: number | null = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

/** Render a FastAPI error `detail` as human-readable text.
 *
 * FastAPI returns validation failures as an array of `{loc, msg, type}`
 * objects; `String(...)` on those yields "[object Object]". */
function formatErrorDetail(detail: unknown): string {
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    const msgs = detail
      .map((item) => (item && typeof item === 'object' && 'msg' in item ? item.msg : item))
      .filter(Boolean)
    if (msgs.length > 0) return msgs.join('; ')
  }
  try {
    return JSON.stringify(detail)
  } catch {
    return String(detail)
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response

  // A content type is set only for a JSON string body.
  //
  // This used to be `init?.body ? 'application/json' : undefined`, which broke every
  // multipart upload: for `FormData` the browser must set the header itself, because only
  // it knows the boundary token. Forcing `application/json` onto a FormData body produces
  // a request the server cannot parse - which is why scan and message upload had to be
  // written against a separate client.
  const headers: Record<string, string> = { accept: 'application/json' }
  if (typeof init?.body === 'string') headers['content-type'] = 'application/json'

  try {
    response = await fetch(`${BACKEND_URL}${path}`, {
      ...init,
      headers: { ...headers, ...(init?.headers as Record<string, string> | undefined) },
      cache: 'no-store',
    })
  } catch {
    throw new ApiError(
      `Could not reach the backend at ${BACKEND_URL}. Is it running on port 8000?`,
      null,
    )
  }

  if (!response.ok) {
    let detail = `Backend responded ${response.status} for ${path}`
    try {
      const errBody = await response.json()
      if (errBody.detail) detail = formatErrorDetail(errBody.detail)
    } catch {}
    throw new ApiError(detail, response.status)
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return {} as T
  }

  return (await response.json()) as T
}

export function fetchBackendHealth(): Promise<BackendHealth> {
  return request<BackendHealth>('/health')
}

/**
 * A page of findings, newest observation first.
 *
 * `asset` filters server-side on an exact match, so drilling into one host from
 * the riskiest-assets panel stays correct past the page size instead of filtering
 * whatever happened to be fetched.
 */
export function fetchFindings(
  limit = 20,
  offset = 0,
  asset?: string,
  status?: FindingStatus,
): Promise<FindingList> {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  if (asset) params.set('asset', asset)
  if (status) params.set('status', status)
  return request<FindingList>(`/findings?${params.toString()}`)
}

/**
 * Queue a re-check of findings after a fix.
 *
 * Returns 202 with a job id: the re-check runs a scan, so the result arrives by
 * polling the findings afterwards rather than in this response. A finding that
 * closes carries a `verification` entry saying what proved it; one that could not
 * be confirmed carries the reason instead.
 */
export function verifyFindings(payload: {
  finding_ids?: string[]
  asset?: string
}): Promise<FindingVerifyResponse> {
  return request<FindingVerifyResponse>('/findings/verify', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function fetchFindingById(id: string): Promise<Finding> {
  return request<Finding>(`/findings/${id}`)
}

export function deleteFinding(id: string): Promise<void> {
  return request<void>(`/findings/${id}`, { method: 'DELETE' })
}

export function fetchFindingSummary(asset: string): Promise<FindingSummary> {
  return request<FindingSummary>(`/findings/summary?asset=${encodeURIComponent(asset)}`)
}

export function runAgent(agent: AgentKind, payload: AgentRunRequest): Promise<AgentRunResponse> {
  return request<AgentRunResponse>(`/agents/${agent}/run`, {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function fetchRuns(limit = 50): Promise<RunList> {
  return request<RunList>(`/runs?limit=${limit}`)
}

export function runDiscovery(): Promise<DiscoveryReport> {
  return request<DiscoveryReport>('/discovery/run', { method: 'POST' })
}

export function createRun(payload: RunCreate): Promise<RunRead> {
  return request<RunRead>('/runs', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function updateRun(id: string, payload: RunUpdate): Promise<RunRead> {
  return request<RunRead>(`/runs/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export function fetchRun(id: string): Promise<RunRead> {
  return request<RunRead>(`/runs/${id}`)
}

export function fetchLatestRun(): Promise<RunRead> {
  return request<RunRead>('/runs/latest')
}

export function fetchRunStatus(): Promise<ScanStatus> {
  return request<ScanStatus>('/runs/status')
}

export function fetchSystemModules(): Promise<SystemModules> {
  return request<SystemModules>('/system/modules')
}

/* ===========================================================================
   Scan intake
   ===========================================================================
   `POST /scans` has existed in the backend since Phase 2 and nothing in the UI has ever
   called it. The Scans page showed *findings grouped by run* instead, so the one path
   that uploads a scanner report was unreachable from a browser.
   =========================================================================== */

/**
 * Upload a scanner report and queue it for analysis.
 *
 * Returns 202 with a scan id; poll `fetchScan` until the status is `completed` or
 * `failed`. Relies on the FormData handling in `request` above.
 */
export function uploadScan(file: File, asset?: string): Promise<Scan> {
  const form = new FormData()
  form.append('file', file)
  if (asset) form.append('asset', asset)
  return request<Scan>('/scans', { method: 'POST', body: form })
}

/** One scan intake record. The poll target after an upload. */
export function fetchScan(id: string): Promise<Scan> {
  return request<Scan>(`/scans/${id}`)
}

export function fetchScans(
  options: { status?: ScanIntakeStatus; limit?: number; offset?: number } = {},
): Promise<ScanList> {
  const params = new URLSearchParams()
  if (options.status) params.set('status', options.status)
  params.set('limit', String(options.limit ?? 50))
  params.set('offset', String(options.offset ?? 0))
  return request<ScanList>(`/scans?${params.toString()}`)
}

/* ===========================================================================
   Message intake — phishing
   ===========================================================================
   Merged in from `lib/intake.ts`, which existed only to avoid a merge conflict while two
   writers shared this file. With one owner that reason is gone, and a single client means
   one `request` implementation rather than two that drift.
   =========================================================================== */

/**
 * Upload an email message for phishing analysis.
 *
 * `enrich` opts in to fetching the linked pages, which is the only step that contacts the
 * suspect host. Off by default, here and on the server.
 */
export function uploadMessage(file: File, enrich = false): Promise<Message> {
  const form = new FormData()
  form.append('file', file)
  form.append('enrich', String(enrich))
  return request<Message>('/messages', { method: 'POST', body: form })
}

/** Submit a bare URL or domain for phishing analysis. */
export function submitUrl(url: string, enrich = false): Promise<Message> {
  return request<Message>('/messages/url', {
    method: 'POST',
    body: JSON.stringify({ url, enrich }),
  })
}

/** One message intake record. The poll target after a submission. */
export function fetchMessage(id: string): Promise<Message> {
  return request<Message>(`/messages/${id}`)
}

export function fetchMessages(
  options: {
    status?: MessageStatus
    verdict?: MessageVerdict
    limit?: number
    offset?: number
  } = {},
): Promise<MessageList> {
  const params = new URLSearchParams()
  if (options.status) params.set('status', options.status)
  if (options.verdict) params.set('verdict', options.verdict)
  params.set('limit', String(options.limit ?? 50))
  params.set('offset', String(options.offset ?? 0))
  return request<MessageList>(`/messages?${params.toString()}`)
}

/** Findings produced by one intake record, scan or message. */
export function fetchFindingsFor(
  key: { scanId: string } | { messageId: string },
  limit = 50,
): Promise<FindingList> {
  const params = new URLSearchParams({ limit: String(limit) })
  if ('scanId' in key) params.set('scan_id', key.scanId)
  else params.set('message_id', key.messageId)
  return request<FindingList>(`/findings?${params.toString()}`)
}

// The settings and email-connect clients were removed with their endpoints. The
// backend stored OAuth client secrets, IMAP passwords and Gmail refresh tokens as
// plaintext rows and served them back over an unauthenticated GET /settings.
// Provider credentials now come from the environment only. Re-adding a mailbox
// integration needs OAuth `state` + PKCE and encrypted token storage first.
