import { useState, useEffect } from 'react'
import { LoginForm } from './LoginForm'
import { ChatArea } from './ChatArea'
import { ApprovalInbox } from './ApprovalInbox'
import { refreshAccessToken, AuthError, type AuthTokens } from '../api/auth'
import type { AgentEvent, ClusterConfig } from '../types'

interface Props {
  cluster: ClusterConfig
  onEvent: (e: AgentEvent) => void
}

export function UserPane({ cluster, onEvent }: Props) {
  const [tokens, setTokens] = useState<AuthTokens | null>(null)
  const [username, setUsername] = useState<string>('')

  function handleLogin(tok: AuthTokens, user: string) {
    setTokens(tok)
    setUsername(user)
  }

  function handleLogout() {
    setTokens(null)
    setUsername('')
  }

  // Refresh the access token shortly before it expires. Each successful refresh
  // sets new tokens, which re-runs this effect and reschedules the next refresh.
  useEffect(() => {
    if (!tokens) return
    const delay = Math.max(0, (tokens.expiresIn - 60) * 1000)
    const timer = setTimeout(() => {
      refreshAccessToken(cluster.authBase, cluster.clientId, tokens.refreshToken)
        .then((next) => setTokens(next))
        .catch((err) => {
          if (err instanceof AuthError) {
            setTokens(null)
            setUsername('')
          }
        })
    }, delay)
    return () => clearTimeout(timer)
  }, [tokens, cluster.authBase, cluster.clientId])

  return (
    <div className="user-pane">
      <div className="pane-header">
        <span className="pane-cluster">{cluster.label}</span>
        {username && <span className="pane-user">{username}</span>}
      </div>

      {tokens ? (
        <>
          <ApprovalInbox cluster={cluster} token={tokens.accessToken} />
          <ChatArea
            cluster={cluster}
            user={username}
            token={tokens.accessToken}
            onEvent={onEvent}
            onLogout={handleLogout}
          />
        </>
      ) : (
        <LoginForm cluster={cluster} onLogin={handleLogin} />
      )}
    </div>
  )
}
