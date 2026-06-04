import { useEffect, useState, useCallback } from 'react'
import { listPendingApprovals, decideApproval, type PendingApproval } from '../api/rag'
import type { ClusterConfig } from '../types'

interface Props {
  cluster: ClusterConfig
  token: string
}

/**
 * Human-in-the-loop approval inbox for the logged-in data owner.
 *
 * Polls the requests this user is entitled to decide (the backend verifies
 * ownership) and lets them Approve/Deny. On approval the requester's access is
 * granted in OpenFGA, so re-asking the original question returns the answer.
 */
export function ApprovalInbox({ cluster, token }: Props) {
  const [pending, setPending] = useState<PendingApproval[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    try {
      setPending(await listPendingApprovals(cluster, token))
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load approvals')
    }
  }, [cluster, token])

  useEffect(() => {
    void refresh()
    const id = setInterval(() => void refresh(), 4000)
    return () => clearInterval(id)
  }, [refresh])

  async function decide(requestId: string, decision: 'approve' | 'deny') {
    setBusy(requestId)
    setError('')
    try {
      await decideApproval(cluster, token, requestId, decision)
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
        🔐 Approval requests<span className="approval-count">{pending.length}</span>
      </div>
      {error && <p className="approval-error">{error}</p>}
      {pending.map((p) => (
        <div key={p.requestId} className="approval-item">
          <div className="approval-item-text">
            A user requests access to answer:
            <span className="approval-query">“{p.query || '(query withheld)'}”</span>
          </div>
          <div className="approval-actions">
            <button
              className="btn-approve"
              disabled={busy === p.requestId}
              onClick={() => void decide(p.requestId, 'approve')}
            >
              {busy === p.requestId ? '…' : 'Approve'}
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
