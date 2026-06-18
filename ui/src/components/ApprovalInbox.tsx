import { useEffect, useRef, useState, useCallback } from 'react'
import { listPendingApprovals, decideApproval, RagError, type PendingApproval } from '../api/rag'
import type { Division } from '../types'

interface Props {
  division: Division
  token: string
}

export function ApprovalInbox({ division, token }: Props) {
  const [pending, setPending] = useState<PendingApproval[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState('')
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const refresh = useCallback(async () => {
    try {
      setPending(await listPendingApprovals(division, token))
      setError('')
    } catch (e) {
      // A 401 means the token is expired — retrying will just repeat the error,
      // so stop polling and prompt re-login. UserPane refreshes the token and
      // passes a new one, which re-runs the effect below and resumes polling.
      if (e instanceof RagError && e.code === '401') {
        setError('Session expired — please log in again')
        if (intervalRef.current !== null) clearInterval(intervalRef.current)
        return
      }
      setError(e instanceof Error ? e.message : 'Failed to load approvals')
    }
  }, [division, token])

  useEffect(() => {
    void refresh()
    intervalRef.current = setInterval(() => void refresh(), 4000)
    return () => {
      if (intervalRef.current !== null) clearInterval(intervalRef.current)
    }
  }, [refresh])

  async function decide(requestId: string, decision: 'approve' | 'deny') {
    setBusy(requestId)
    setError('')
    try {
      await decideApproval(division, token, requestId, decision)
      setPending((prev) => prev.filter((p) => p.requestId !== requestId))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Decision failed')
    } finally {
      setBusy(null)
      void refresh()
    }
  }

  if (pending.length === 0 && !error) return null

  return (
    <div className="approval-inbox">
      <div className="approval-inbox-title">
        <span>&#x1F510; Approval requests</span>
        <span className="approval-count">{pending.length}</span>
      </div>
      {error && <p className="approval-error">{error}</p>}
      {pending.map((p) => (
        <div key={p.requestId} className="approval-item">
          <div className="approval-item-text">
            <span>A user requests access to answer:</span>
            <span className="approval-query">
              {p.query ? `"${p.query}"` : '(query text unavailable)'}
            </span>
          </div>
          <div className="approval-actions">
            <button
              className="btn-approve"
              disabled={busy === p.requestId}
              onClick={() => void decide(p.requestId, 'approve')}
            >
              {busy === p.requestId ? '...' : 'Approve'}
            </button>
            <button
              className="btn-deny"
              disabled={busy === p.requestId}
              onClick={() => void decide(p.requestId, 'deny')}
            >
              Deny
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}
