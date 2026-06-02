import { useState } from 'react'
import { LoginForm } from './LoginForm'
import { ChatArea } from './ChatArea'
import type { AgentEvent, ClusterConfig } from '../types'

interface Props {
  cluster: ClusterConfig
  onEvent: (e: AgentEvent) => void
}

export function UserPane({ cluster, onEvent }: Props) {
  const [token, setToken] = useState<string | null>(null)
  const [username, setUsername] = useState<string>('')

  function handleLogin(tok: string, user: string) {
    setToken(tok)
    setUsername(user)
  }

  function handleLogout() {
    setToken(null)
    setUsername('')
  }

  return (
    <div className="user-pane">
      <div className="pane-header">
        <span className="pane-cluster">{cluster.label}</span>
        {username && <span className="pane-user">{username}</span>}
      </div>

      {token ? (
        <ChatArea
          cluster={cluster}
          user={username}
          token={token}
          onEvent={onEvent}
          onLogout={handleLogout}
        />
      ) : (
        <LoginForm cluster={cluster} onLogin={handleLogin} />
      )}
    </div>
  )
}
