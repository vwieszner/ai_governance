import type { AgentEvent, ClusterConfig, EventKind, NormalizedTask, TaskState } from '../types'

export type TaskCallback = (task: NormalizedTask) => void
export type EventCallback = (event: AgentEvent) => void

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


// ── Cluster-A: POST /tasks/send → SSE task_status_update events ──────────────

async function submitQueryClusterA(
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

  const res = await fetch(`${cluster.apiBase}/tasks/send`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
    },
    body: JSON.stringify({
      id: taskId,
      message: {
        role: 'user',
        parts: [{ type: 'text', text: query }],
        messageId: crypto.randomUUID(),
        taskId,
      },
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
    // The federated-rag backend generates the answer server-side and streams it
    // inside task_status_update events (answer is in the task history).
    if (event !== 'task_status_update') continue

    let parsed: Record<string, unknown>
    try { parsed = JSON.parse(data) } catch { continue }

    const status = (parsed['status'] as Record<string, unknown>) ?? {}
    const state = (status['state'] as TaskState) ?? 'working'
    const statusMessage = (status['message'] as string) ?? ''
    const history = (parsed['history'] as unknown[]) ?? []
    const metadata = (parsed['metadata'] as Record<string, unknown>) ?? {}

    let answer = ''
    for (let i = history.length - 1; i >= 0; i--) {
      const msg = history[i] as Record<string, unknown>
      if (msg['role'] === 'agent') {
        const parts = (msg['parts'] as Record<string, unknown>[]) ?? []
        const textPart = parts.find((p) => p['type'] === 'text')
        answer = (textPart?.['text'] as string) ?? ''
        break
      }
    }

    task.state = state
    task.statusMessage = statusMessage
    task.answer = answer
    task.flow = (metadata['flow'] as string) ?? task.flow
    task.approvalRequestId = (metadata['approvalRequestId'] as string | null) ?? task.approvalRequestId
    task.peerTaskId = (metadata['peerTaskId'] as string | null) ?? task.peerTaskId
    task.updatedAt = new Date()
    onTask({ ...task })
    onEvent(makeEvent(cluster, user, inferKind(statusMessage, state), taskId, statusMessage || state))
  }
}

// ── Unified entry point ───────────────────────────────────────────────────────

// Both clusters run the same federated-rag (A2A) codebase, so both speak the
// A2A protocol: POST /tasks/send with task_status_update SSE events. There is no
// separate /query path anymore.
export function submitQuery(
  cluster: ClusterConfig,
  user: string,
  token: string,
  query: string,
  onTask: TaskCallback,
  onEvent: EventCallback,
): Promise<void> {
  return submitQueryClusterA(cluster, user, token, query, onTask, onEvent)
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
    headers: { Authorization: `Bearer ${token}` },
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
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision }),
    },
  )
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new RagError(`Decision failed (${res.status}): ${text}`, String(res.status))
  }
}
