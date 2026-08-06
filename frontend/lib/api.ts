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
  FindingSummary,
  AgentRunRequest,
  AgentRunResponse,
  AgentKind,
  Setting,
  DiscoveryReport,
  RunCreate,
  RunUpdate,
  RunRead,
  RunList,
  ScanStatus,
  SystemModules,
  EmailConnectionStatus,
  EmailScanResponse,
} from '@/lib/types'

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

export function fetchFindings(limit = 20, offset = 0): Promise<FindingList> {
  return request<FindingList>(`/findings?limit=${limit}&offset=${offset}`)
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

export function fetchSettings(): Promise<Setting[]> {
  return request<Setting[]>('/settings')
}

export function updateSetting(key: string, value: string): Promise<Setting> {
  return request<Setting>('/settings', {
    method: 'POST',
    body: JSON.stringify({ key, value }),
  })
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

// --------------------------------------------------------------------------
// Email OAuth integration
// --------------------------------------------------------------------------

export function fetchEmailStatus(): Promise<EmailConnectionStatus> {
  return request<EmailConnectionStatus>('/email/status')
}

export type EmailProvider = 'google' | 'microsoft' | 'imap'

export function emailScan(provider: EmailProvider, limit = 20): Promise<EmailScanResponse> {
  return request<EmailScanResponse>('/email/scan', {
    method: 'POST',
    body: JSON.stringify({ provider, limit }),
  })
}

export function emailDisconnect(provider: EmailProvider): Promise<void> {
  return request<void>(`/email/disconnect/${provider}`, { method: 'DELETE' })
}

export interface ImapConnectPayload {
  email: string
  host: string
  port: number
  password: string
  folder: string
}

export function imapConnect(payload: ImapConnectPayload): Promise<EmailConnectionStatus> {
  return request<EmailConnectionStatus>('/email/connect/imap', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

/** Returns the backend URL to redirect the browser to for OAuth consent. */
export function emailConnectUrl(provider: 'google' | 'microsoft'): string {
  return `${BACKEND_URL}/email/connect/${provider}`
}
