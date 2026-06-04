import { useState, type FormEvent } from 'react'
import { getToken, AuthError, type AuthTokens } from '../api/auth'
import type { ClusterConfig } from '../types'

interface Props {
  cluster: ClusterConfig
  onLogin: (tokens: AuthTokens, username: string) => void
}

export function LoginForm({ cluster, onLogin }: Props) {
  const [username, setUsername] = useState(cluster.defaultUser)
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const tokens = await getToken(cluster.authBase, cluster.clientId, username, password)
      onLogin(tokens, username)
    } catch (err) {
      setError(err instanceof AuthError ? err.message : 'Login failed — check credentials')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-form">
      <p className="login-hint">
        Connect to <strong>{cluster.id}</strong>
      </p>
      <form onSubmit={handleSubmit}>
        <label>
          Username
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            spellCheck={false}
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>
        {error && <p className="login-error">{error}</p>}
        <button
          type="submit"
          disabled={loading}
          className={`btn-primary${loading ? ' btn-loading' : ''}`}
        >
          {loading ? 'Connecting…' : 'Login'}
        </button>
      </form>
    </div>
  )
}
