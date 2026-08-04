/**
 * Backend API client.
 *
 * NEXT_PUBLIC_BACKEND_URL is read by the browser, so it must be a URL the
 * browser can reach - localhost:8000, not the compose service name.
 */

import type { BackendHealth, FindingList } from '@/lib/types'

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
      headers: { accept: 'application/json', ...init?.headers },
      cache: 'no-store',
    })
  } catch {
    throw new ApiError(
      `Could not reach the backend at ${BACKEND_URL}. Is it running on port 8000?`,
      null,
    )
  }

  if (!response.ok) {
    throw new ApiError(`Backend responded ${response.status} for ${path}`, response.status)
  }

  return (await response.json()) as T
}

export function fetchBackendHealth(): Promise<BackendHealth> {
  return request<BackendHealth>('/health')
}

export function fetchFindings(limit = 20): Promise<FindingList> {
  return request<FindingList>(`/findings?limit=${limit}`)
}
