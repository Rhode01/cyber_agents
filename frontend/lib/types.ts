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

export interface AgentTraceEntry {
  type: 'tool_call' | 'tool_result'
  tool?: string
  args?: unknown
  tool_call_id?: string
  result?: string
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

export interface FindingSummary {
  asset: string
  count: number
  severities: Record<string, number>
  findings: Finding[]
}

export interface AgentRunRequest {
  source: string
  asset?: string | null
  /** Optional untrusted tool output. When omitted, the agent launches its own scan against `asset`. */
  raw_input?: string
  context?: Record<string, unknown>
  persist?: boolean
  background?: boolean
}

export interface AgentRunResponse {
  agent: AgentKind
  mode: 'inline' | 'background'
  persisted: boolean
  job_id?: string | null
  findings: Finding[]
}

export interface Setting {
  key: string
  value: string
  description?: string | null
}
