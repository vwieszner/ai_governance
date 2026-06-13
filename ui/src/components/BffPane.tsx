import { useEffect, useState } from 'react'
import { ChatArea } from './ChatArea'
import { ApprovalInbox } from './ApprovalInbox'
import { setCsrf } from '../api/rag'
import { getSession, login, logout, type BffSession } from '../api/session'
import type { AgentEvent, ClusterConfig } from '../types'

interface Props {
  cluster: ClusterConfig
  onEvent: (e: AgentEvent) => void
}

// Production auth pane: the browser holds NO token. Auth state comes from /bff/session
// (HttpOnly cookie); login/logout are server-driven redirects. The CSRF token from the
// session is handed to the fetch layer for mutating calls.
export function BffPane({ cluster, onEvent }: Props) {
  const [session, setSession] = useState<BffSession | null>(null)

  useEffect(() => {
    getSession()
      .then((s) => {
        setSession(s)
        if (s.authenticated && s.csrf_token) setCsrf(s.csrf_token)
      })
      .catch(() => setSession({ authenticated: false }))
  }, [])

  return (
    <div className="user-pane">
      <div className="pane-header">
        <span className="pane-cluster">{cluster.label}</span>
        {session?.authenticated && <span className="pane-user">{session.user}</span>}
      </div>

      {session === null ? (
        <p className="chat-empty">Checking session…</p>
      ) : session.authenticated ? (
        <>
          <ApprovalInbox cluster={cluster} token="" />
          {/* token="" => cookie mode (no token in JS); auth rides the HttpOnly cookie */}
          <ChatArea
            cluster={cluster}
            user={session.user ?? 'user'}
            token=""
            onEvent={onEvent}
            onLogout={() => void logout(session.csrf_token ?? '')}
          />
        </>
      ) : (
        <div className="login-form">
          <p className="login-hint">Sign in to <strong>{cluster.label}</strong></p>
          <button type="button" className="btn-primary" onClick={() => login()}>
            Sign in with SSO
          </button>
        </div>
      )}
    </div>
  )
}
