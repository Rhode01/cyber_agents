/**
 * Types mirroring the backend's HTTP surface.
 *
 * Phase 1 keeps these hand-written. Generating them from the backend's OpenAPI
 * schema - which is itself generated from the shared cyberagents_contracts
 * package - is deferred to a later phase.
 */

export type AgentKind = 'vulnerability' | 'phishing' | 'network' | 'webapp'

export const AGENT_KINDS: AgentKind[] = ['vulnerability', 'phishing', 'network', 'webapp']

/** How the Run Agent pipeline decides which detection agents to launch. */
export type PipelineMode = 'auto' | 'manual'

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

/** What kind of problem a finding describes. Orthogonal to severity. */
export type FindingType =
  | 'outdated_service'
  | 'risky_exposed_service'
  | 'known_cve'
  | 'weak_configuration'
  | 'prompt_injection_attempt'
  | 'informational'

export type FindingStatus = 'new' | 'triaged' | 'resolved' | 'false_positive'

/** One factor's contribution to a finding's remediation priority.
 *
 * Computed deterministically by the ai.engine, never by a model, so it can be
 * shown to an analyst as the reason for a ranking. Lives under
 * `evidence.priority`. */
export interface PriorityFactor {
  value: string
  points: number
  max_points: number
}

export interface FindingPriority {
  score: number
  max_score: number
  rank: number
  factors: Record<string, PriorityFactor>
}

/** What one re-check concluded about a finding.
 *
 * Only `resolved` closes a finding, and only when the scan provably covered its
 * host and port. `unverified` means the check could not reach it — an offline
 * host, a refused target, a port outside the scanned range — and must be shown as
 * prominently as a resolution, or the loop becomes a source of false confidence.
 * `unverifiable` means no network scan can ever cover it, e.g. a package finding
 * with no port. Lives under `evidence.verification` as a list, newest last. */
export type VerificationOutcome =
  | 'resolved'
  | 'still_present'
  | 'unverified'
  | 'unverifiable'

export interface VerificationEntry {
  outcome: VerificationOutcome
  reason: string
  verified_at: string
  recorded_at: string
  /** `scan://<id>` or `recheck://<job>` — what drove this attempt. */
  source: string
}

/** Acknowledgement that a re-check has been queued. */
export interface FindingVerifyResponse {
  queued: number
  job_id: string | null
  detail: string
}

export interface Finding {
  id: string
  agent: AgentKind
  finding_type: FindingType
  title: string
  description: string
  severity: Severity
  confidence: number
  source: string
  asset: string | null
  /** Service name from a banner. UNTRUSTED - render as text. */
  service: string | null
  port: number | null
  protocol: string | null
  /** Only ever produced by the rule engine, never by a model. */
  cve_ids: string[]
  /** Untrusted data captured from a monitored system. Render as text, never as markup. */
  evidence: Record<string, unknown>
  recommendation: string | null
  status: FindingStatus
  raw_reference: string | null
  /** The pipeline run that produced this finding, when there was one. */
  run_id: string | null
  /** The uploaded scan that produced this finding, when there was one. */
  scan_id: string | null
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
  /** Link the returned findings to a pipeline run so they group as one scan session. */
  run_id?: string
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

export interface InterfaceInfo {
  name: string
  ip: string
  prefix: number
  subnet: string
}

export interface WebHost {
  host: string
  ports: number[]
  urls: string[]
}

export interface ServicePort {
  host: string
  port: number
  protocol: string
  /** Nmap service name, e.g. ssh. */
  service: string | null
  /** Product banner, e.g. OpenSSH. */
  product: string | null
  /** Product version, e.g. 7.2. */
  version: string | null
  extra_info: string | null
}

export interface DiscoveryReport {
  interfaces: InterfaceInfo[]
  subnets: string[]
  live_hosts: string[]
  web_hosts: WebHost[]
  services: ServicePort[]
  duration_seconds: number
  notes: string[]
}

/** Pipeline configuration chosen in the UI for one run. */
export interface PipelineConfig {
  mode: PipelineMode
  agents: AgentKind[]
  mailSource: string
}

/** Overall state of a persisted pipeline run. */
export type RunStatus = 'running' | 'completed' | 'completed_with_errors' | 'failed'

/** Per-agent snapshot stored in the run. `count` is the finding count so a
 * refreshed page can render progress without re-fetching every finding. */
export interface AgentStatusSnapshot {
  state: 'pending' | 'running' | 'skipped' | 'done' | 'error'
  count: number
  error?: string
}

export interface RunCreate {
  target: string
  mode: PipelineMode
}

export interface RunUpdate {
  status?: RunStatus
  agent_statuses?: Record<AgentKind, AgentStatusSnapshot>
  discovery?: DiscoveryReport | null
}

export interface RunRead {
  id: string
  target: string
  mode: PipelineMode
  status: RunStatus
  agent_statuses: Record<AgentKind, AgentStatusSnapshot>
  discovery: DiscoveryReport | null
  started_at: string
  finished_at: string | null
  created_at: string
  updated_at: string
}

export interface RunList {
  items: RunRead[]
  total: number
}

/** Backend /runs/status: whether a scan is in flight right now. */
export interface ScanStatus {
  scanning: boolean
  current: RunRead | null
}

export interface ModuleStatus {
  name: string
  host: string
  status: 'ok' | 'down' | 'unknown'
  detail: string
}

export interface SystemModules {
  items: ModuleStatus[]
}

// EmailConnectionStatus and EmailScanResponse were removed with the mailbox
// integration. See the note in src/lib/api.ts.
