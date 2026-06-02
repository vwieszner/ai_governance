import { describe, it, expect, vi, afterEach } from 'vitest'
import { submitQuery } from './rag'
import { CLUSTER_A, CLUSTER_B } from '../types'
import type { NormalizedTask, AgentEvent } from '../types'

// ---------------------------------------------------------------------------
// SSE stream helpers
// ---------------------------------------------------------------------------

/**
 * Encodes a raw SSE string into a ReadableStream-compatible reader.
 * parseSSE in rag.ts calls reader.read() + releaseLock().
 */
function makeSSEReader(sseText: string) {
  const encoded = new TextEncoder().encode(sseText)
  return {
    read: vi.fn().mockImplementationOnce(async () => ({ done: false, value: encoded }))
                 .mockImplementationOnce(async () => ({ done: true,  value: undefined })),
    releaseLock: vi.fn(),
  }
}

/**
 * Builds a successful fetch Response whose body streams the given SSE text.
 */
function makeSSEResponse(sseText: string): Response {
  const reader = makeSSEReader(sseText)
  return {
    ok: true,
    status: 200,
    body: { getReader: () => reader },
    text: async () => '',
  } as unknown as Response
}

/**
 * Builds a failed fetch Response (no body stream needed — error path uses res.text()).
 */
function makeErrorResponse(status: number, body: string): Response {
  return {
    ok: false,
    status,
    text: async () => body,
    body: null,
  } as unknown as Response
}

// ---------------------------------------------------------------------------
// Cluster-A SSE fixture
// event: task_status_update  (two events: working → completed)
// ---------------------------------------------------------------------------
function clusterASSE(taskId: string): string {
  const working = JSON.stringify({
    status: { state: 'working', message: 'Retrieving documents' },
    history: [],
    metadata: { flow: 'local' },
  })

  const agentPart = { type: 'text', text: 'The answer is 42.' }
  const completed = JSON.stringify({
    status: { state: 'completed', message: 'Done processing' },
    history: [
      { role: 'user',  parts: [{ type: 'text', text: 'What is the answer?' }] },
      { role: 'agent', parts: [agentPart] },
    ],
    metadata: { flow: 'local', taskId },
  })

  // Each SSE block must be separated by \n\n; trailing \n\n ensures last block is flushed.
  return (
    `event: task_status_update\ndata: ${working}\n\n` +
    `event: task_status_update\ndata: ${completed}\n\n`
  )
}

// ---------------------------------------------------------------------------
// Cluster-B SSE fixture
// events: status → result → done
// ---------------------------------------------------------------------------
function clusterBSSE(): string {
  const status = JSON.stringify({ status: 'Retrieving documents' })
  const result = JSON.stringify({
    answer: 'The answer is 42.',
    status_message: 'Completed',
    flow: 'local',
    approval_request_id: null,
    peer_task_id: null,
  })

  return (
    `event: status\ndata: ${status}\n\n` +
    `event: result\ndata: ${result}\n\n` +
    `event: done\ndata: {}\n\n`
  )
}

// ---------------------------------------------------------------------------
// Shared: capture callbacks
// ---------------------------------------------------------------------------
function makeCallbacks() {
  return {
    onTask:  vi.fn<[NormalizedTask], void>(),
    onEvent: vi.fn<[AgentEvent], void>(),
  }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('submitQuery — cluster-a', () => {
  it('calls onEvent(query_sent) before fetch, then fires task + event per SSE update', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async () => {
        // taskId is chosen inside submitQueryClusterA before fetch; capture it
        // from the request body so we can build a matching fixture
        return makeSSEResponse(clusterASSE('any'))
      }),
    )

    const { onTask, onEvent } = makeCallbacks()

    await submitQuery(CLUSTER_A, 'alice', 'tok-abc', 'What is the answer?', onTask, onEvent)

    // onEvent should have been called at least 3 times:
    //   [0] query_sent (before fetch)
    //   [1] agent_working (working update)
    //   [2] completed (completed update)
    expect(onEvent).toHaveBeenCalledTimes(3)
    expect(onEvent.mock.calls[0][0].kind).toBe('query_sent')
    expect(onEvent.mock.calls[1][0].kind).toBe('agent_working')
    expect(onEvent.mock.calls[2][0].kind).toBe('completed')

    // onTask should have been called twice (once per SSE event)
    expect(onTask).toHaveBeenCalledTimes(2)

    // First task update: state = working
    const firstTask = onTask.mock.calls[0][0]
    expect(firstTask.state).toBe('working')
    expect(firstTask.statusMessage).toBe('Retrieving documents')

    // Last task update: state = completed with the agent answer
    const lastTask = onTask.mock.calls.at(-1)![0]
    expect(lastTask.state).toBe('completed')
    expect(lastTask.answer).toBe('The answer is 42.')
  })

  it('POSTs to the correct cluster-a endpoint with auth header', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeSSEResponse(clusterASSE('any'))))

    const { onTask, onEvent } = makeCallbacks()
    await submitQuery(CLUSTER_A, 'alice', 'my-token', 'Test query', onTask, onEvent)

    const fetchMock = vi.mocked(fetch)
    expect(fetchMock).toHaveBeenCalledOnce()
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/a/tasks/send')
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer my-token')
    expect((init.headers as Record<string, string>)['Accept']).toBe('text/event-stream')
  })

  it('throws on HTTP error response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(makeErrorResponse(500, 'Internal Server Error')),
    )

    const { onTask, onEvent } = makeCallbacks()
    await expect(
      submitQuery(CLUSTER_A, 'alice', 'tok', 'query', onTask, onEvent),
    ).rejects.toThrow('Submit failed 500')
  })
})

describe('submitQuery — cluster-b', () => {
  it('fires query_sent, submitted task, then status/result/done updates', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeSSEResponse(clusterBSSE())))

    const { onTask, onEvent } = makeCallbacks()
    await submitQuery(CLUSTER_B, 'bob', 'tok-xyz', 'What is the answer?', onTask, onEvent)

    // onEvent: query_sent + agent_working (status) + completed (result) + completed (done)
    expect(onEvent).toHaveBeenCalledTimes(4)
    expect(onEvent.mock.calls[0][0].kind).toBe('query_sent')
    expect(onEvent.mock.calls[1][0].kind).toBe('agent_working')   // status event
    expect(onEvent.mock.calls[3][0].kind).toBe('completed')        // done event

    // onTask: submitted (before fetch) + working (status) + result (completed)
    // done event does NOT call onTask again because state is already completed
    expect(onTask).toHaveBeenCalledTimes(3)

    // First call: submitted state (before fetch, before SSE)
    expect(onTask.mock.calls[0][0].state).toBe('submitted')

    // Last task update: state=completed with answer
    const lastTask = onTask.mock.calls.at(-1)![0]
    expect(lastTask.state).toBe('completed')
    expect(lastTask.answer).toBe('The answer is 42.')
    expect(lastTask.statusMessage).toBe('Completed')
  })

  it('POSTs to the correct cluster-b endpoint with auth header', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeSSEResponse(clusterBSSE())))

    const { onTask, onEvent } = makeCallbacks()
    await submitQuery(CLUSTER_B, 'bob', 'my-token', 'Test query', onTask, onEvent)

    const fetchMock = vi.mocked(fetch)
    expect(fetchMock).toHaveBeenCalledOnce()
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/b/query')
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer my-token')
    expect((init.headers as Record<string, string>)['Accept']).toBe('text/event-stream')

    // Body should contain just { query }
    const body = JSON.parse(init.body as string)
    expect(body).toEqual({ query: 'Test query' })
  })

  it('throws on HTTP error response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(makeErrorResponse(500, 'Server error')),
    )

    const { onTask, onEvent } = makeCallbacks()
    await expect(
      submitQuery(CLUSTER_B, 'bob', 'tok', 'query', onTask, onEvent),
    ).rejects.toThrow('Submit failed 500')
  })
})
