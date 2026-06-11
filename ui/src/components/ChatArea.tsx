import { useState, useRef, useEffect, type KeyboardEvent } from 'react'
import { TaskMessage } from './TaskMessage'
import { submitQuery, pollApprovalResult } from '../api/rag'
import type { AgentEvent, ClusterConfig, NormalizedTask } from '../types'

interface Props {
  cluster: ClusterConfig
  user: string
  token: string
  onEvent: (e: AgentEvent) => void
  onLogout: () => void
}

export function ChatArea({ cluster, user, token, onEvent, onLogout }: Props) {
  const [input, setInput] = useState('')
  const [tasks, setTasks] = useState<NormalizedTask[]>([])
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)
  const lastTask = tasks[tasks.length - 1]

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lastTask?.id, lastTask?.state])

  function upsertTask(updated: NormalizedTask) {
    setTasks((prev) => {
      const idx = prev.findIndex((t) => t.id === updated.id)
      if (idx === -1) return [...prev, updated]
      const next = [...prev]
      next[idx] = updated
      return next
    })
  }

  // Requester-side approval polling. When a question is parked on 'input-required'
  // (pending a data owner's approval), poll the server for the outcome. The answer
  // (or denial) arrives over the network once the approver decides — the two users
  // never share a browser. The server re-checks THIS user's authorization before
  // releasing any answer.
  const tasksRef = useRef(tasks)
  useEffect(() => { tasksRef.current = tasks }, [tasks])
  const hasPending = tasks.some((t) => t.state === 'input-required')
  useEffect(() => {
    if (!hasPending) return
    const id = setInterval(() => {
      const pending = tasksRef.current.filter((t) => t.state === 'input-required')
      for (const t of pending) {
        // Poll the SERVER's task id (the backend ignores the client-generated one);
        // fall back to t.id only if the result event hasn't landed yet.
        pollApprovalResult(cluster, token, t.serverTaskId ?? t.id)
          .then((r) => {
            if (r.status === 'completed') {
              upsertTask({ ...t, state: 'completed', answer: r.answer || '', statusMessage: 'Approved', updatedAt: new Date() })
              onEvent({
                id: crypto.randomUUID(), timestamp: new Date(), cluster: cluster.id,
                user, kind: 'completed', taskId: t.id,
                message: '✅ Data owner approved — answer delivered to requester',
              })
            } else if (r.status === 'denied') {
              upsertTask({ ...t, state: 'failed', answer: '', statusMessage: r.message || 'Your request was declined by the data owner.', updatedAt: new Date() })
              onEvent({
                id: crypto.randomUUID(), timestamp: new Date(), cluster: cluster.id,
                user, kind: 'failed', taskId: t.id,
                message: '⛔ Data owner declined the request',
              })
            }
          })
          .catch(() => { /* transient — keep polling */ })
      }
    }, 4000)
    return () => clearInterval(id)
  }, [hasPending, cluster, token, user, onEvent])

  async function handleSubmit() {
    const query = input.trim()
    if (!query || submitting) return
    setInput('')
    setError('')
    setSubmitting(true)
    try {
      await submitQuery(cluster, user, token, query, upsertTask, onEvent)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request failed')
    } finally {
      setSubmitting(false)
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      void handleSubmit()
    }
  }

  return (
    <div className="chat-area">
      <div className="chat-header">
        <span className="chat-user">{user}</span>
        <span className="chat-cluster">{cluster.id}</span>
        <button className="btn-logout" onClick={onLogout} title="Log out">✕</button>
      </div>

      <div className="chat-messages">
        {tasks.length === 0 && (
          <p className="chat-empty">
            Ask a question to query the knowledge base.
            <br />
            <span style={{ fontSize: '11px' }}>Shift+Enter for a new line · Enter to send</span>
          </p>
        )}
        {tasks.map((t) => (
          <TaskMessage key={t.id} task={t} />
        ))}
        {error && <p className="chat-error">{error}</p>}
        <div ref={bottomRef} />
      </div>

      <div className="chat-input-row">
        <textarea
          className="chat-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask a question…"
          rows={2}
          disabled={submitting}
        />
        <button
          className="btn-send"
          onClick={() => void handleSubmit()}
          disabled={submitting || !input.trim()}
          title="Send (Enter)"
        >
          {submitting ? '…' : '▶'}
        </button>
      </div>
    </div>
  )
}
