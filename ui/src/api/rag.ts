import type { AgentEvent, ClusterConfig, EventKind, NormalizedTask, TaskState } from '../types'

export type TaskCallback = (task: NormalizedTask) => void
export type EventCallback = (event: AgentEvent) => void

// BFF mode: the browser holds no token — auth rides the HttpOnly session cookie. We send
// `credentials: 'include'` everywhere, attach the CSRF token (from /bff/session) on mutating
// requests, and only add an Authorization header when a token is actually present (password
// mode). One helper so every call is consistent.
let _csrf = ''
export function setCsrf(token: string): void { _csrf = token }

function authHeaders(token: string, mutating: boolean): Record<string, string> {
  const h: Record<string, string> = {}
  if (token) h['Authorization'] = `Bearer ${token}`
  if (mutating && _csrf) h['X-CSRF-Token'] = _csrf
  return h
}

export class RagError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message)
    this.name = 'RagError'
  }
}

function makeEvent(
  cluster: ClusterConfig,
  user: string,
  kind: EventKind,
  taskId: string,
  message: string,
): AgentEvent {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date(),
    cluster: cluster.id,
    user,
    kind,
    taskId,
    message,
  }
}

function inferKind(message: string, state: TaskState): EventKind {
  const m = message.toLowerCase()
  if (m.includes('peer') || m.includes('cluster') || m.includes('delegat')) return 'peer_call'
  if (m.includes('approval') || state === 'input-required') return 'approval_needed'
  if (state === 'completed') return 'completed'
  if (state === 'failed') return 'failed'
  if (m.includes('working') || m.includes('retrieving') || m.includes('processing')) return 'agent_working'
  return 'raw_update'
}

// Shared helper: parse a single SSE block into { event, data } or null if empty
function parseSingleBlock(block: string): { event: string; data: string } | null {
  if (!block.trim()) return null
  const lines = block.split(/\n|\r\n/)
  let eventName = 'message'
  let data = ''
  for (const line of lines) {
    if (line.startsWith('event:')) eventName = line.slice(6).trim()
    else if (line.startsWith('data:')) data = line.slice(5).trim()
  }
  return data ? { event: eventName, data } : null
}

// Parse SSE blocks from text (works whether we got the response buffered or streaming)
function* parseSSEText(text: string): Generator<{ event: string; data: string }> {
  const blocks = text.split(/\n\n|\r\n\r\n/)
  for (const block of blocks) {
    const parsed = parseSingleBlock(block)
    if (parsed) yield parsed
  }
}

// Streaming SSE reader — used when response.body is available (real browser streaming)
async function* parseSSEStream(
  response: Response,
): AsyncGenerator<{ event: string; data: string }> {
  const reader = response.body!.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      const blocks = buffer.split(/\n\n|\r\n\r\n/)
      buffer = blocks.pop() ?? ''
      for (const block of blocks) {
        const parsed = parseSingleBlock(block)
        if (parsed) yield parsed
      }
    }
    // Flush anything left in the buffer after stream ends
    if (buffer.trim()) {
      for (const ev of parseSSEText(buffer + '\n\n')) yield ev
    }
  } finally {
    reader.releaseLock()
  }
}

// Unified SSE reader — streams if possible, falls back to buffered text
async function* readSSE(
  response: Response,
): AsyncGenerator<{ event: string; data: string }> {
  if (response.body) {
    yield* parseSSEStream(response)
  } else {
    // Proxy buffered the whole response — parse it all at once
    const text = await response.text()
    for (const ev of parseSSEText(text)) yield ev
  }
}

/**
 * Create an initial task shell.
 *
 * @param id - Caller-supplied stable unique identifier (generated via
 *   `crypto.randomUUID()` at the call site).  `upsertTask` in ChatArea uses
 *   this id to find and update the existing task row in state.
 * @param query - The user query string shown in the chat bubble.
 */
function blankTask(id: string, query: string): NormalizedTask {
  const now = new Date()
  return {
    id,
    serverTaskId: null,
    query,
    state: 'submitted',
    statusMessage: '',
    answer: '',
    flow: '',
    approvalRequestId: null,
    peerTaskId: null,
    createdAt: now,
    updatedAt: now,
  }
}


// ── AGT cluster: POST /query → status / result / done SSE events ─────────────

async function submitQueryAGT(
  cluster: ClusterConfig,
  user: string,
  token: string,
  query: string,
  onTask: TaskCallback,
  onEvent: EventCallback,
): Promise<void> {
  const taskId = crypto.randomUUID()

  // Show the query bubble immediately — don't wait for the first SSE event
  const task = blankTask(taskId, query)
  onTask({ ...task })
  onEvent(makeEvent(cluster, user, 'query_sent', taskId, query))

  const res = await fetch(`${cluster.apiBase}/query`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      ...authHeaders(token, true),
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
    },
    body: JSON.stringify({
      query,
      task_id: taskId,
      context_id: crypto.randomUUID(),
    }),
  })

  if (!res.ok) {
    const text = await res.text().catch(() => '')
    task.state = 'failed'
    task.statusMessage = `Error ${res.status}: ${text}`
    onTask({ ...task })
    const code = res.status === 401 ? '401' : res.status === 429 ? '429' : res.status >= 500 ? '500' : String(res.status)
    throw new RagError(task.statusMessage, code)
  }

  task.state = 'working'
  onTask({ ...task })

  for await (const { event, data } of readSSE(res)) {
    if (event === 'status') {
      // {"status":"working"} — keep the row in the working state
      task.state = 'working'
      task.updatedAt = new Date()
      onTask({ ...task })
      onEvent(makeEvent(cluster, user, 'agent_working', taskId, 'working'))
      continue
    }

    if (event === 'error') {
      // Governance denial or backend exception — surfaced AFTER the stream opens
      let message = 'Request failed'
      try {
        const parsed = JSON.parse(data) as Record<string, unknown>
        message = (parsed['error'] as string) ?? message
      } catch { /* keep default */ }
      task.state = 'failed'
      task.statusMessage = message
      task.updatedAt = new Date()
      onTask({ ...task })
      onEvent(makeEvent(cluster, user, 'failed', taskId, message))
      continue
    }

    if (event === 'result') {
      let parsed: Record<string, unknown>
      try { parsed = JSON.parse(data) } catch { continue }

      const answer = (parsed['answer'] as string) ?? ''
      const statusMessage = (parsed['status_message'] as string) ?? ''
      const flow = (parsed['flow'] as string) ?? ''
      const approvalRequestId = (parsed['approval_request_id'] as string | null) ?? null
      const serverTaskId = (parsed['task_id'] as string | null) ?? null

      // Classify like the AGT backend's own a2a_query mapper. Key on the approval
      // signals FIRST. format_response overwrites a None answer with the
      // (LLM-generated, not literally "pending") status_message, so the approval case
      // carries a non-empty answer — keying on answer alone would misclassify it as
      // completed and the approval prompt never shows. `flow` carries *_needs_approval
      // for BOTH the local case (approvalRequestId set) AND the cross-division case
      // (approvalRequestId is null on this side — the peer holds it), so it is the
      // reliable signal to enter the polling state.
      let state: TaskState
      if (approvalRequestId) state = 'input-required'
      else if (flow.toLowerCase().includes('needs_approval')) state = 'input-required'
      else if (statusMessage.toLowerCase().includes('pending')) state = 'input-required'
      else if (answer) state = 'completed'
      else state = 'working'

      task.state = state
      task.answer = answer
      task.statusMessage = statusMessage
      task.flow = flow || task.flow
      task.approvalRequestId = approvalRequestId ?? task.approvalRequestId
      // Adopt the SERVER's task_id so the requester-side approval poll targets the
      // record the backend actually stored (it ignores the client-supplied id).
      task.serverTaskId = serverTaskId ?? task.serverTaskId
      task.updatedAt = new Date()
      onTask({ ...task })
      onEvent(makeEvent(cluster, user, inferKind(statusMessage, state), taskId, statusMessage || state))
      continue
    }

    // event === 'done' (or unknown): stream ended — nothing more to emit
  }
}

// ── Unified entry point ───────────────────────────────────────────────────────

// AGT clusters speak POST /query with status/result/done SSE events.
export function submitQuery(
  cluster: ClusterConfig,
  user: string,
  token: string,
  query: string,
  onTask: TaskCallback,
  onEvent: EventCallback,
): Promise<void> {
  return submitQueryAGT(cluster, user, token, query, onTask, onEvent)
}

// ── Approval outcome polling (requester side) ────────────────────────────────
//
// After a request goes 'pending approval', the requester's client polls the
// server for the outcome. This is the cross-machine delivery channel: the answer
// (or denial) comes back over the network once the approver decides — the two
// users do NOT need to share a browser. The server re-checks the requester's
// authorization before releasing any answer.

export interface ApprovalOutcome {
  status: 'pending' | 'completed' | 'denied'
  answer?: string
  message?: string
}

export async function pollApprovalResult(
  cluster: ClusterConfig,
  token: string,
  taskId: string,
): Promise<ApprovalOutcome> {
  const res = await fetch(
    `${cluster.apiBase}/tasks/${encodeURIComponent(taskId)}/result`,
    { credentials: 'include', headers: authHeaders(token, false) },
  )
  if (!res.ok) {
    throw new RagError(`Failed to poll approval result (${res.status})`, String(res.status))
  }
  return (await res.json()) as ApprovalOutcome
}

// ── Approval inbox (human-in-the-loop) ───────────────────────────────────────
//
// The data owner (this logged-in user) fetches the access requests they are
// entitled to decide and records an approve/deny decision. Backend verifies the
// caller is the designated owner (real attribution); the requester never learns
// the request_id. Temporal's namespace is shared across clusters, so polling
// this user's own cluster surfaces requests that originated on either cluster.

export interface PendingApproval {
  requestId: string
  requesterId: string
  query: string
}

export async function listPendingApprovals(
  cluster: ClusterConfig,
  token: string,
): Promise<PendingApproval[]> {
  const res = await fetch(`${cluster.apiBase}/approvals/pending`, {
    credentials: 'include', headers: authHeaders(token, false),
  })
  if (!res.ok) {
    throw new RagError(`Failed to load approvals (${res.status})`, String(res.status))
  }
  const data = (await res.json()) as { pending?: Array<Record<string, string>> }
  return (data.pending ?? []).map((p) => ({
    requestId: p.request_id,
    requesterId: p.requester_id,
    query: p.query,
  }))
}

export async function decideApproval(
  cluster: ClusterConfig,
  token: string,
  requestId: string,
  decision: 'approve' | 'deny',
): Promise<void> {
  const res = await fetch(
    `${cluster.apiBase}/approvals/${encodeURIComponent(requestId)}/decision`,
    {
      method: 'POST',
      credentials: 'include',
      headers: { ...authHeaders(token, true), 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision }),
    },
  )
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new RagError(`Decision failed (${res.status}): ${text}`, String(res.status))
  }
}
