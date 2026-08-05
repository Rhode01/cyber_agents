/**
 * Backend API client.
 *
 * NEXT_PUBLIC_BACKEND_URL is read by the browser, so it must be a URL the
 * browser can reach - localhost:8000, not the compose service name.
 */

import type { BackendHealth, Finding, FindingList, FindingSummary, AgentRunRequest, AgentRunResponse, AgentKind, Setting } from '@/lib/types'

export const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL ?? 'http://localhost:8000'

export class ApiError extends Error {
  readonly status: number | null

  constructor(message: string, status: number | null = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
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
      if (errBody.detail) detail = String(errBody.detail)
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

export function fetchFindings(limit = 20): Promise<FindingList> {
  return request<FindingList>(`/findings?limit=${limit}`)
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

export function fetchSettings(): Promise<Setting[]> {
  return request<Setting[]>('/settings')
}

export function updateSetting(key: string, value: string): Promise<Setting> {
  return request<Setting>('/settings', {
    method: 'POST',
    body: JSON.stringify({ key, value }),
  })
}
