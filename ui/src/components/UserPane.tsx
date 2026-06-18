import { useState, useEffect } from 'react'
import { LoginForm } from './LoginForm'
import { ChatArea } from './ChatArea'
import { ApprovalInbox } from './ApprovalInbox'
import { refreshAccessToken, AuthError, type AuthTokens } from '../api/auth'
import type { AgentEvent, Division } from '../types'

interface Props {
  division: Division
  onEvent: (e: AgentEvent) => void
}

export function UserPane({ division, onEvent }: Props) {
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
      refreshAccessToken(division.authBase, division.clientId, tokens.refreshToken)
        .then((next) => setTokens(next))
        .catch((err) => {
          if (err instanceof AuthError) {
            setTokens(null)
            setUsername('')
          }
        })
    }, delay)
    return () => clearTimeout(timer)
  }, [tokens, division.authBase, division.clientId])

  return (
    <div className="user-pane">
      <div className="pane-header">
        <span className="pane-division">{division.label}</span>
        {username && <span className="pane-user">{username}</span>}
      </div>

      {tokens ? (
        <>
          <ApprovalInbox division={division} token={tokens.accessToken} />
          <ChatArea
            division={division}
            user={username}
            token={tokens.accessToken}
            onEvent={onEvent}
            onLogout={handleLogout}
          />
        </>
      ) : (
        <LoginForm division={division} onLogin={handleLogin} />
      )}
    </div>
  )
}
