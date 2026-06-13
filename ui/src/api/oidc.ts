// OIDC Authorization-Code + PKCE for the SPA — the production login path that works
// against ANY OIDC IdP (Keycloak, Entra ID, Okta, Auth0, …) with NO client secret in the
// browser. Discovery-driven, so per-IdP differences are configuration, not code.
//
// Why this exists alongside the password-grant login: ROPC (password grant) is blocked by
// most corporate IdPs once MFA / Conditional Access is on. PKCE redirects the user to
// THEIR IdP (which handles MFA, SSO cookies, etc.) and returns an authorization code the
// SPA exchanges for tokens using a one-time code_verifier — no shared secret required.
//
// Enabled by VITE_AUTH_MODE=pkce; the bundled two-pane demo keeps password grant.

export interface OidcConfig {
  authority: string // issuer URL, e.g. https://login.microsoftonline.com/<tenant>/v2.0
  clientId: string
  redirectUri: string
  scope: string // e.g. "openid email profile"
}

export interface OidcEndpoints {
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint?: string
}

const STORAGE_VERIFIER = 'oidc.pkce.verifier'
const STORAGE_STATE = 'oidc.pkce.state'

// ── PKCE primitives (RFC 7636) ────────────────────────────────────────────────

function base64UrlEncode(bytes: ArrayBuffer): string {
  const b = String.fromCharCode(...new Uint8Array(bytes))
  return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function randomString(len = 64): string {
  const arr = new Uint8Array(len)
  crypto.getRandomValues(arr)
  // URL-safe charset; length ~len.
  return base64UrlEncode(arr.buffer).slice(0, len)
}

export async function generatePkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = randomString(64)
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: base64UrlEncode(digest) }
}

// ── Discovery ──────────────────────────────────────────────────────────────────

export async function discover(authority: string): Promise<OidcEndpoints> {
  const url = authority.replace(/\/$/, '') + '/.well-known/openid-configuration'
  const res = await fetch(url)
  if (!res.ok) throw new Error(`OIDC discovery failed (${res.status}) at ${url}`)
  const doc = await res.json()
  if (!doc.authorization_endpoint || !doc.token_endpoint) {
    throw new Error('OIDC discovery document missing authorization/token endpoint')
  }
  return doc as OidcEndpoints
}

// ── Authorize redirect ──────────────────────────────────────────────────────────

export function buildAuthorizeUrl(
  cfg: OidcConfig,
  endpoints: OidcEndpoints,
  pkce: { challenge: string; state: string },
): string {
  const p = new URLSearchParams({
    response_type: 'code',
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    scope: cfg.scope,
    state: pkce.state,
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256',
  })
  return `${endpoints.authorization_endpoint}?${p.toString()}`
}

/** Kick off login: generate PKCE, stash verifier+state, redirect to the IdP. */
export async function beginLogin(cfg: OidcConfig): Promise<void> {
  const endpoints = await discover(cfg.authority)
  const { verifier, challenge } = await generatePkce()
  const state = randomString(32)
  sessionStorage.setItem(STORAGE_VERIFIER, verifier)
  sessionStorage.setItem(STORAGE_STATE, state)
  window.location.assign(buildAuthorizeUrl(cfg, endpoints, { challenge, state }))
}

// ── Callback / token exchange ───────────────────────────────────────────────────

export interface CallbackParams {
  code: string
  state: string
}

/** Parse ?code=&state= from a redirect URL search string; null if not a callback. */
export function parseCallback(search: string): CallbackParams | null {
  const q = new URLSearchParams(search)
  const code = q.get('code')
  const state = q.get('state')
  if (!code || !state) return null
  return { code, state }
}

export interface OidcTokens {
  accessToken: string
  refreshToken: string
  expiresIn: number
}

export async function completeLogin(cfg: OidcConfig, cb: CallbackParams): Promise<OidcTokens> {
  const expectedState = sessionStorage.getItem(STORAGE_STATE)
  const verifier = sessionStorage.getItem(STORAGE_VERIFIER)
  if (!expectedState || cb.state !== expectedState) {
    throw new Error('OIDC state mismatch — possible CSRF; aborting token exchange')
  }
  if (!verifier) throw new Error('OIDC code_verifier missing from session — restart login')

  const endpoints = await discover(cfg.authority)
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: cfg.clientId,
    code: cb.code,
    redirect_uri: cfg.redirectUri,
    code_verifier: verifier,
  })
  const res = await fetch(endpoints.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })
  // One-time material — clear regardless of outcome.
  sessionStorage.removeItem(STORAGE_VERIFIER)
  sessionStorage.removeItem(STORAGE_STATE)
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`Token exchange failed (${res.status}): ${text.slice(0, 200)}`)
  }
  const json = await res.json()
  if (!json.access_token) throw new Error('No access_token in token response')
  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token ?? '',
    expiresIn: json.expires_in ?? 0,
  }
}

export function readEnvConfig(): OidcConfig | null {
  const env = import.meta.env
  if ((env.VITE_AUTH_MODE ?? 'password') !== 'pkce') return null
  const authority = env.VITE_OIDC_AUTHORITY
  const clientId = env.VITE_OIDC_CLIENT_ID
  if (!authority || !clientId) return null
  return {
    authority,
    clientId,
    redirectUri: env.VITE_OIDC_REDIRECT_URI || window.location.origin + '/',
    scope: env.VITE_OIDC_SCOPE || 'openid email profile',
  }
}
