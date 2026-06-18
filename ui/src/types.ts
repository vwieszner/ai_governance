export type TaskState =
  | 'submitted'
  | 'working'
  | 'input-required'
  | 'completed'
  | 'failed'
  | 'canceled'

export interface NormalizedTask {
  id: string
  /** The id the SERVER stored this task under (returned in the `result` SSE event).
   *  The requester-side approval poll (GET /tasks/{id}/result) must use THIS id, not
   *  the client-generated `id` — the backend generates its own task_id and ignores
   *  the one the client sends. */
  serverTaskId: string | null
  query: string
  state: TaskState
  statusMessage: string
  answer: string
  flow: string
  approvalRequestId: string | null
  peerTaskId: string | null
  createdAt: Date
  updatedAt: Date
}

export type EventKind =
  | 'query_sent'
  | 'agent_working'
  | 'peer_call'
  | 'approval_needed'
  | 'completed'
  | 'failed'
  | 'raw_update'

export interface AgentEvent {
  id: string
  timestamp: Date
  /** The id of the division this event belongs to (Division.id). N-capable: any
   *  configured division id, not a fixed two-value set. */
  division: string
  user: string
  kind: EventKind
  taskId: string
  message: string
}

/**
 * A division: one physically-isolated tenant with its own OIDC issuer and agent.
 * The product is division-native (N divisions, per-division issuer/audience); the UI
 * models divisions as a configurable list, not a hardcoded pair.
 */
export interface Division {
  /** Stable identifier (used as React key, in events, and in the monitor). */
  id: string
  /** Human-readable display name shown in the pane header and login. */
  label: string
  /** Pre-filled username for the bundled demo (optional in real deployments). */
  defaultUser: string
  /** OIDC public client id registered at this division's IdP. */
  clientId: string
  /** Vite proxy path to this division's agent API (POST /query, /tasks, …).
   *  Never a localhost URL — the browser only ever talks to the Vite origin. */
  apiBase: string
  /** Vite proxy path to this division's OIDC token endpoint base. */
  authBase: string
  /** Backend wire protocol: 'agt' = POST /query (AgentMesh DID federation). */
  protocol: 'agt'
}

// ── Division configuration ───────────────────────────────────────────────────
//
// Divisions are configured (not hardcoded to two). Two ways, in priority order:
//
//   1. VITE_DIVISIONS — a JSON array of partial Division objects, e.g.
//        VITE_DIVISIONS='[{"id":"alpha","label":"Division Alpha","apiBase":"/api/agt-a","authBase":"/auth/a"}]'
//      Each entry is merged over the defaults below (sensible clientId/protocol).
//      This is the N-division knob: add a 3rd/4th division here + a matching Vite
//      proxy entry, with no code change.
//
//   2. Per-division label overrides (back-compat): VITE_CLUSTER_A_LABEL /
//      VITE_CLUSTER_B_LABEL relabel the two default divisions.
//
// If neither is set, the bundled two-division demo (alpha + beta) is used so the
// split-pane demo keeps working out of the box.

const DEFAULTS = {
  clientId: 'rag-ui',
  protocol: 'agt' as const,
}

// The bundled demo's two divisions (alpha + beta). apiBase / authBase are Vite proxy
// paths — never localhost URLs.
const DEFAULT_DIVISIONS: Division[] = [
  {
    id: 'alpha',
    label: import.meta.env.VITE_CLUSTER_A_LABEL ?? 'Division Alpha',
    defaultUser: 'alice',
    clientId: DEFAULTS.clientId,
    apiBase: '/api/agt-a',
    authBase: '/auth/a',
    protocol: DEFAULTS.protocol,
  },
  {
    id: 'beta',
    label: import.meta.env.VITE_CLUSTER_B_LABEL ?? 'Division Beta',
    defaultUser: 'bob',
    clientId: DEFAULTS.clientId,
    apiBase: '/api/agt-b',
    authBase: '/auth/b',
    protocol: DEFAULTS.protocol,
  },
]

/** Coerce one VITE_DIVISIONS JSON entry into a complete Division, filling defaults. */
function normalizeDivision(raw: unknown, index: number): Division {
  const o = (raw ?? {}) as Partial<Division>
  const id = o.id ?? `division-${index + 1}`
  if (!o.apiBase || !o.authBase) {
    throw new Error(
      `VITE_DIVISIONS[${index}] (id="${id}") must define apiBase and authBase`,
    )
  }
  return {
    id,
    label: o.label ?? id,
    defaultUser: o.defaultUser ?? '',
    clientId: o.clientId ?? DEFAULTS.clientId,
    apiBase: o.apiBase,
    authBase: o.authBase,
    protocol: o.protocol ?? DEFAULTS.protocol,
  }
}

/** Parse VITE_DIVISIONS (JSON array) into Divisions, or null if unset/blank. */
export function parseDivisionsEnv(value: string | undefined): Division[] | null {
  const raw = (value ?? '').trim()
  if (!raw) return null
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('VITE_DIVISIONS is not valid JSON')
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error('VITE_DIVISIONS must be a non-empty JSON array')
  }
  return parsed.map(normalizeDivision)
}

/**
 * Ordered list of all divisions shown in the UI. App.tsx maps this array to panes,
 * so the pane count follows the configured division count — N panes, not two.
 */
export const DIVISIONS: Division[] = parseDivisionsEnv(import.meta.env.VITE_DIVISIONS) ?? DEFAULT_DIVISIONS

/** The primary division (used by BFF single-session mode, which is one division per browser). */
export const PRIMARY_DIVISION: Division = DIVISIONS[0]
