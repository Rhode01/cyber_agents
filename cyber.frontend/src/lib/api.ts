/**
 * Backend API client.
 *
 * NEXT_PUBLIC_BACKEND_URL is read by the browser, so it must be a URL the
 * browser can reach - localhost:8000, not the compose service name.
 */

import type {
  BackendHealth,
  Finding,
  FindingList,
  FindingStatus,
  FindingSummary,
  FindingVerifyResponse,
  AgentRunRequest,
  AgentRunResponse,
  AgentKind,
  DiscoveryReport,
  RunCreate,
  RunUpdate,
  RunRead,
  RunList,
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

  try {
    response = await fetch(`${BACKEND_URL}${path}`, {
      ...init,
      headers: { 
        accept: 'application/json',
        'Content-Type': init?.body ? 'application/json' : undefined,
        ...init?.headers 
      } as HeadersInit,
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

// The settings and email-connect clients were removed with their endpoints. The
// backend stored OAuth client secrets, IMAP passwords and Gmail refresh tokens as
// plaintext rows and served them back over an unauthenticated GET /settings.
// Provider credentials now come from the environment only. Re-adding a mailbox
// integration needs OAuth `state` + PKCE and encrypted token storage first.
