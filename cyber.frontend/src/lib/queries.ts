'use client'

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from '@tanstack/react-query'

import * as api from '@/lib/api'
import {
  TERMINAL_INTAKE_STATUSES,
  type AgentKind,
  type AgentRunRequest,
  type FindingStatus,
  type Message,
  type MessageVerdict,
  type RunCreate,
  type RunUpdate,
  type Scan,
  type ScanScopeCreate,
} from '@/types'

/**
 * Every server interaction in the application.
 *
 * `lib/api.ts` stays the transport — this layer owns caching, polling and invalidation.
 * Before it, each page hand-rolled its own `useEffect` with a `cancelled` flag, an error
 * boolean and a `setInterval`: 45 such blocks across the pages plus 4 more in the sidebar.
 * Consistent loading and error states are not really achievable on top of that, because
 * every view invents its own notion of "loading".
 *
 * Two things worth knowing before adding a hook here:
 *
 * **Polling stops.** Intake queries poll only while the record is non-terminal, then stop.
 * The previous sidebar polled `/runs/status` every four seconds forever, including on pages
 * that never showed it.
 *
 * **Keys are hierarchical**, so a mutation can invalidate a whole family — writing one
 * finding invalidates every findings list without needing to know which filters are open.
 */

/* ---------------------------------------------------------------- keys */

export const queryKeys = {
  health: ['health'] as const,
  systemModules: ['system', 'modules'] as const,

  findings: {
    all: ['findings'] as const,
    list: (filters: FindingFilters) => ['findings', 'list', filters] as const,
    detail: (id: string) => ['findings', 'detail', id] as const,
    summary: (asset: string) => ['findings', 'summary', asset] as const,
    forIntake: (key: IntakeKey) => ['findings', 'intake', key] as const,
  },

  runs: {
    all: ['runs'] as const,
    list: (limit: number) => ['runs', 'list', limit] as const,
    latest: ['runs', 'latest'] as const,
    status: ['runs', 'status'] as const,
  },

  scans: {
    all: ['scans'] as const,
    list: (limit: number) => ['scans', 'list', limit] as const,
    detail: (id: string) => ['scans', 'detail', id] as const,
  },

  scanScope: {
    all: ['scan-scope'] as const,
    list: (includeRevoked: boolean) => ['scan-scope', 'list', includeRevoked] as const,
  },

  messages: {
    all: ['messages'] as const,
    list: (filters: MessageFilters) => ['messages', 'list', filters] as const,
    detail: (id: string) => ['messages', 'detail', id] as const,
  },
} as const

export interface FindingFilters {
  limit?: number
  offset?: number
  asset?: string
  status?: FindingStatus
}

export interface MessageFilters {
  verdict?: MessageVerdict
  limit?: number
}

type IntakeKey = { scanId: string } | { messageId: string }

/** How long a completed intake or a finding stays fresh before a refetch on focus. */
const FRESH_FOR = 30_000
const POLL_INTERVAL = 2_000

/**
 * Polling for an artifact a worker is still processing.
 *
 * Three settings that only make sense together:
 *
 * `refetchInterval` returns `false` once the record reaches a terminal status, so a finished
 * intake stops costing requests. That is the behaviour the hand-rolled version had to express
 * with an attempt counter and a cancelled flag in every component.
 *
 * `refetchIntervalInBackground` is on, against React Query's default. It is normally right to
 * stop polling a hidden tab, but the whole point of the progress stepper is live progress, and
 * the realistic use is submit-then-switch-away-for-ten-seconds. Without this the analyst comes
 * back to a stale "Queued" on a scan that finished while they were gone. The cost is bounded by
 * the same terminal check: this polls for the seconds an intake actually takes, not forever.
 *
 * `staleTime: 0` because the global 15s default would otherwise suppress the refetch that
 * `refetchOnWindowFocus` fires on return — the one moment the value is most wrong.
 */
const INTAKE_POLLING = {
  refetchInterval: (query: { state: { data?: { status: string } | undefined } }) =>
    isTerminal(query.state.data?.status) ? false : POLL_INTERVAL,
  refetchIntervalInBackground: true,
  staleTime: 0,
} as const

/* ------------------------------------------------------------- platform */

export function useHealth() {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: api.fetchBackendHealth,
    // The shell shows this; a stale value for a minute is fine and it must never be the
    // reason a page thunks.
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1,
  })
}

export function useSystemModules() {
  return useQuery({
    queryKey: queryKeys.systemModules,
    queryFn: api.fetchSystemModules,
    staleTime: 30_000,
    refetchInterval: 30_000,
    retry: 1,
  })
}

/**
 * Whether a browser-driven run is in flight.
 *
 * One query shared by the shell and the Run page. It replaces the sidebar's private
 * four-second interval, which ran on every route whether or not anything displayed it.
 */
export function useRunStatus() {
  return useQuery({
    queryKey: queryKeys.runs.status,
    queryFn: api.fetchRunStatus,
    refetchInterval: 5_000,
    retry: 1,
  })
}

/* ------------------------------------------------------------- findings */

export function useFindings(filters: FindingFilters = {}) {
  const { limit = 200, offset = 0, asset, status } = filters
  return useQuery({
    queryKey: queryKeys.findings.list({ limit, offset, asset, status }),
    queryFn: () => api.fetchFindings(limit, offset, asset, status),
    staleTime: FRESH_FOR,
  })
}

export function useFinding(id: string | undefined) {
  return useQuery({
    queryKey: queryKeys.findings.detail(id ?? ''),
    queryFn: () => api.fetchFindingById(id as string),
    enabled: Boolean(id),
    staleTime: FRESH_FOR,
  })
}

export function useFindingSummary(asset: string | undefined) {
  return useQuery({
    queryKey: queryKeys.findings.summary(asset ?? ''),
    queryFn: () => api.fetchFindingSummary(asset as string),
    enabled: Boolean(asset),
    staleTime: FRESH_FOR,
  })
}

/** The findings one intake produced. Enabled only once the intake has finished. */
export function useIntakeFindings(key: IntakeKey | null, ready: boolean) {
  return useQuery({
    queryKey: queryKeys.findings.forIntake(key ?? { scanId: '' }),
    queryFn: () => api.fetchFindingsFor(key as IntakeKey),
    enabled: Boolean(key) && ready,
    staleTime: FRESH_FOR,
  })
}

export function useDeleteFinding() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.deleteFinding(id),
    onSuccess: () => {
      // The whole family: the list, the summaries and any intake view could all change.
      void client.invalidateQueries({ queryKey: queryKeys.findings.all })
    },
  })
}

export function useVerifyFindings() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (payload: { finding_ids?: string[]; asset?: string }) =>
      api.verifyFindings(payload),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.findings.all })
    },
  })
}

/* ----------------------------------------------------------------- runs */

export function useRuns(limit = 8) {
  return useQuery({
    queryKey: queryKeys.runs.list(limit),
    queryFn: () => api.fetchRuns(limit),
    staleTime: FRESH_FOR,
  })
}

export function useLatestRun() {
  return useQuery({
    queryKey: queryKeys.runs.latest,
    queryFn: api.fetchLatestRun,
    // A 404 here means "no run yet", which is a normal state rather than a failure.
    retry: false,
  })
}

export function useCreateRun() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (payload: RunCreate) => api.createRun(payload),
    onSuccess: () => void client.invalidateQueries({ queryKey: queryKeys.runs.all }),
  })
}

export function useUpdateRun() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: RunUpdate }) =>
      api.updateRun(id, payload),
    onSuccess: () => void client.invalidateQueries({ queryKey: queryKeys.runs.all }),
  })
}

export function useRunAgent() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ agent, payload }: { agent: AgentKind; payload: AgentRunRequest }) =>
      api.runAgent(agent, payload),
    onSuccess: () => void client.invalidateQueries({ queryKey: queryKeys.findings.all }),
  })
}

export function useRunDiscovery() {
  return useMutation({ mutationFn: api.runDiscovery })
}

/* ----------------------------------------------------------- scan scope */

export function useScanScope(includeRevoked = false) {
  return useQuery({
    queryKey: queryKeys.scanScope.list(includeRevoked),
    queryFn: () => api.fetchScanScope(includeRevoked),
    staleTime: FRESH_FOR,
  })
}

export function useAddScanScope() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (payload: ScanScopeCreate) => api.addScanScope(payload),
    onSuccess: () => void client.invalidateQueries({ queryKey: queryKeys.scanScope.all }),
  })
}

export function useRevokeScanScope() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.revokeScanScope(id),
    onSuccess: () => void client.invalidateQueries({ queryKey: queryKeys.scanScope.all }),
  })
}

/* ---------------------------------------------------------------- scans */

export function useScans(limit = 50) {
  return useQuery({
    queryKey: queryKeys.scans.list(limit),
    queryFn: () => api.fetchScans({ limit }),
    staleTime: FRESH_FOR,
  })
}

/**
 * One scan, polled while the worker is still on it.
 *
 * `refetchInterval` returns false once the record reaches a terminal status, so a finished
 * scan stops costing requests. That is the behaviour the hand-rolled version had to
 * express with an attempt counter and a cancelled flag in every component.
 */
export function useScan(id: string | undefined): UseQueryResult<Scan> {
  return useQuery({
    queryKey: queryKeys.scans.detail(id ?? ''),
    queryFn: () => api.fetchScan(id as string),
    enabled: Boolean(id),
    ...INTAKE_POLLING,
  })
}

export function useUploadScan(): UseMutationResult<
  Scan,
  Error,
  { file: File; asset?: string }
> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ file, asset }) => api.uploadScan(file, asset),
    onSuccess: () => void client.invalidateQueries({ queryKey: queryKeys.scans.all }),
  })
}

/* ------------------------------------------------------------- messages */

export function useMessages(filters: MessageFilters = {}) {
  const { limit = 20, verdict } = filters
  return useQuery({
    queryKey: queryKeys.messages.list({ limit, verdict }),
    queryFn: () => api.fetchMessages({ limit, verdict }),
    staleTime: FRESH_FOR,
  })
}

/** One message, polled while non-terminal. Same rationale as `useScan`. */
export function useMessage(id: string | undefined): UseQueryResult<Message> {
  return useQuery({
    queryKey: queryKeys.messages.detail(id ?? ''),
    queryFn: () => api.fetchMessage(id as string),
    enabled: Boolean(id),
    ...INTAKE_POLLING,
  })
}

export function useUploadMessage(): UseMutationResult<
  Message,
  Error,
  { file: File; enrich: boolean }
> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ file, enrich }) => api.uploadMessage(file, enrich),
    onSuccess: () => void client.invalidateQueries({ queryKey: queryKeys.messages.all }),
  })
}

export function useSubmitUrl(): UseMutationResult<
  Message,
  Error,
  { url: string; enrich: boolean }
> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ url, enrich }) => api.submitUrl(url, enrich),
    onSuccess: () => void client.invalidateQueries({ queryKey: queryKeys.messages.all }),
  })
}

/* --------------------------------------------------------------- shared */

function isTerminal(status: string | undefined): boolean {
  return status !== undefined && TERMINAL_INTAKE_STATUSES.includes(status as never)
}

/**
 * Once an intake finishes, its findings become worth fetching.
 *
 * Exported as a helper rather than inlined so the Scans and Phishing pages express
 * "wait for the worker, then read the result" the same way.
 */
export function intakeIsFinished(status: string | undefined): boolean {
  return isTerminal(status)
}
