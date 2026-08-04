/**
 * Types mirroring the backend's HTTP surface.
 *
 * Phase 1 keeps these hand-written. Generating them from the backend's OpenAPI
 * schema - which is itself generated from the shared cyberagents_contracts
 * package - is deferred to a later phase.
 */

export type AgentKind = 'vulnerability' | 'phishing' | 'network' | 'webapp'

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface BackendHealth {
  status: 'ok'
  service: string
  version: string
  app_env: string
}

export interface Finding {
  id: string
  agent: AgentKind
  title: string
  description: string
  severity: Severity
  confidence: number
  source: string
  asset: string | null
  /** Untrusted data captured from a monitored system. Render as text, never as markup. */
  evidence: Record<string, unknown>
  recommendation: string | null
  raw_reference: string | null
  detected_at: string
  created_at: string
}

export interface FindingList {
  items: Finding[]
  total: number
  limit: number
  offset: number
}
