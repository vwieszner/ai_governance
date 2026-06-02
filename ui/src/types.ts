export type TaskState =
  | 'submitted'
  | 'working'
  | 'input-required'
  | 'completed'
  | 'failed'
  | 'canceled'

export interface NormalizedTask {
  id: string
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
  cluster: 'cluster-a' | 'cluster-b'
  user: string
  kind: EventKind
  taskId: string
  message: string
}

export type ClusterId = 'cluster-a' | 'cluster-b'

export interface ClusterConfig {
  id: ClusterId
  /** Human-readable display name shown in the pane header */
  label: string
  defaultUser: string
  clientId: string
  apiBase: string
  authBase: string
}

// Labels are configurable via VITE_CLUSTER_A_LABEL / VITE_CLUSTER_B_LABEL in .env.demo.
// apiBase / authBase are Vite proxy paths — never localhost URLs.
export const CLUSTER_A: ClusterConfig = {
  id: 'cluster-a',
  label: import.meta.env.VITE_CLUSTER_A_LABEL ?? 'Cluster A',
  defaultUser: 'alice',
  clientId: 'rag-ui',
  apiBase: '/api/a',
  authBase: '/auth/a',
}

export const CLUSTER_B: ClusterConfig = {
  id: 'cluster-b',
  label: import.meta.env.VITE_CLUSTER_B_LABEL ?? 'Cluster B',
  defaultUser: 'bob',
  clientId: 'rag-ui',
  apiBase: '/api/b',
  authBase: '/auth/b',
}

/**
 * Ordered list of all clusters in the demo.
 * App.tsx maps this array to panes, so adding a third cluster is one env var
 * change + one vite proxy entry — no App.tsx edit needed.
 */
export const CLUSTERS: ClusterConfig[] = [CLUSTER_A, CLUSTER_B]
