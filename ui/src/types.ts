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
  cluster: 'cluster-agt-a' | 'cluster-agt-b'
  user: string
  kind: EventKind
  taskId: string
  message: string
}

export type ClusterId = 'cluster-agt-a' | 'cluster-agt-b'

export interface ClusterConfig {
  id: ClusterId
  /** Human-readable display name shown in the pane header */
  label: string
  defaultUser: string
  clientId: string
  apiBase: string
  authBase: string
  /** Backend wire protocol: 'agt' = POST /query (AgentMesh DID federation) */
  protocol: 'agt'
}

// Labels are configurable via VITE_CLUSTER_A_LABEL / VITE_CLUSTER_B_LABEL in the env file.
// apiBase / authBase are Vite proxy paths — never localhost URLs.
export const CLUSTER_AGT_A: ClusterConfig = {
  id: 'cluster-agt-a',
  label: import.meta.env.VITE_CLUSTER_A_LABEL ?? 'AGT Cluster A',
  defaultUser: 'alice',
  clientId: 'rag-ui',
  apiBase: '/api/agt-a',
  authBase: '/auth/a',
  protocol: 'agt',
}

export const CLUSTER_AGT_B: ClusterConfig = {
  id: 'cluster-agt-b',
  label: import.meta.env.VITE_CLUSTER_B_LABEL ?? 'AGT Cluster B',
  defaultUser: 'bob',
  clientId: 'rag-ui',
  apiBase: '/api/agt-b',
  authBase: '/auth/b',
  protocol: 'agt',
}

/**
 * Ordered list of all clusters shown in the UI.
 * App.tsx maps this array to panes, so adding a cluster is one config entry
 * + one vite proxy entry — no App.tsx edit needed.
 */
export const CLUSTERS: ClusterConfig[] = [CLUSTER_AGT_A, CLUSTER_AGT_B]
