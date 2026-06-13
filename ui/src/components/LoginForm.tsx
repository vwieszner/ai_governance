import { useState, type FormEvent } from 'react'
import { getToken, AuthError, type AuthTokens } from '../api/auth'
import { beginLogin, readEnvConfig } from '../api/oidc'
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

  // Production SSO path: when VITE_AUTH_MODE=pkce is configured, offer a redirect to the
  // corporate IdP instead of the password form (which most IdPs block under MFA).
  const oidc = readEnvConfig()
  if (oidc) {
    return (
      <div className="login-form">
        <p className="login-hint">
          Sign in to <strong>{cluster.label}</strong>
        </p>
        <button
          type="button"
          className="btn-primary"
          onClick={() => { void beginLogin(oidc).catch((e) => setError(String(e))) }}
        >
          Sign in with SSO
        </button>
        {error && <p className="login-error">{error}</p>}
      </div>
    )
  }

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
