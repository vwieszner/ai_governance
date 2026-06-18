import { useState, type FormEvent } from 'react'
import { getToken, AuthError, type AuthTokens } from '../api/auth'
import { beginLogin, readEnvConfig } from '../api/oidc'
import type { Division } from '../types'

interface Props {
  division: Division
  onLogin: (tokens: AuthTokens, username: string) => void
}

export function LoginForm({ division, onLogin }: Props) {
  const [username, setUsername] = useState(division.defaultUser)
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // Production SSO path: when VITE_AUTH_MODE=pkce is configured, offer a redirect to the
  // corporate IdP instead of the password form (which most IdPs block under MFA).
  const oidc = readEnvConfig()
  if (oidc) {
    return (
      <div className="login-form">
        <DivisionBadge division={division} />
        <p className="login-hint">
          Sign in to <strong>{division.label}</strong>
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
      // Authenticate against THIS division's OIDC issuer (per-division audience/issuer).
      const tokens = await getToken(division.authBase, division.clientId, username, password)
      onLogin(tokens, username)
    } catch (err) {
      setError(err instanceof AuthError ? err.message : 'Login failed — check credentials')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-form">
      <DivisionBadge division={division} />
      <p className="login-hint">
        Sign in to <strong>{division.label}</strong>
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

// Makes the user's division explicit at login (FR-2.4): a clearly-labeled badge naming
// the division this credential authenticates against (its own issuer/audience).
function DivisionBadge({ division }: { division: Division }) {
  return (
    <div className="login-division" data-division={division.id}>
      <span className="login-division-tag">Division</span>
      <span className="login-division-name">{division.label}</span>
    </div>
  )
}
