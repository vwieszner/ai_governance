// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest'
import {
  generatePkce,
  buildAuthorizeUrl,
  parseCallback,
  completeLogin,
  type OidcConfig,
  type OidcEndpoints,
} from './oidc'

const CFG: OidcConfig = {
  authority: 'https://idp.example.com',
  clientId: 'rag-ui',
  redirectUri: 'http://localhost:5173/',
  scope: 'openid email profile',
}
const ENDPOINTS: OidcEndpoints = {
  authorization_endpoint: 'https://idp.example.com/authorize',
  token_endpoint: 'https://idp.example.com/token',
}

afterEach(() => {
  vi.unstubAllGlobals()
  sessionStorage.clear()
})

describe('PKCE', () => {
  it('generates a verifier and a matching S256 challenge', async () => {
    const { verifier, challenge } = await generatePkce()
    expect(verifier.length).toBeGreaterThanOrEqual(43) // RFC 7636 min
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/) // base64url, no padding
    expect(challenge).not.toContain('=')
    // verifier and challenge differ (challenge is the hash, not the verifier)
    expect(challenge).not.toEqual(verifier)
  })

  it('produces a different verifier each call', async () => {
    const a = await generatePkce()
    const b = await generatePkce()
    expect(a.verifier).not.toEqual(b.verifier)
  })
})

describe('buildAuthorizeUrl', () => {
  it('includes PKCE + required OIDC params', () => {
    const url = buildAuthorizeUrl(CFG, ENDPOINTS, { challenge: 'CH', state: 'ST' })
    const u = new URL(url)
    expect(u.origin + u.pathname).toBe('https://idp.example.com/authorize')
    expect(u.searchParams.get('response_type')).toBe('code')
    expect(u.searchParams.get('client_id')).toBe('rag-ui')
    expect(u.searchParams.get('code_challenge')).toBe('CH')
    expect(u.searchParams.get('code_challenge_method')).toBe('S256')
    expect(u.searchParams.get('state')).toBe('ST')
    expect(u.searchParams.get('redirect_uri')).toBe('http://localhost:5173/')
  })
})

describe('parseCallback', () => {
  it('extracts code+state and rejects non-callbacks', () => {
    expect(parseCallback('?code=abc&state=xyz')).toEqual({ code: 'abc', state: 'xyz' })
    expect(parseCallback('?error=access_denied')).toBeNull()
    expect(parseCallback('')).toBeNull()
  })
})

describe('completeLogin', () => {
  it('rejects a state mismatch (CSRF guard) without calling the token endpoint', async () => {
    sessionStorage.setItem('oidc.pkce.state', 'expected')
    sessionStorage.setItem('oidc.pkce.verifier', 'v')
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    await expect(completeLogin(CFG, { code: 'c', state: 'ATTACKER' })).rejects.toThrow(/state mismatch/i)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('exchanges the code with the verifier and returns tokens', async () => {
    sessionStorage.setItem('oidc.pkce.state', 'ST')
    sessionStorage.setItem('oidc.pkce.verifier', 'VERIFIER123')
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      if (url.includes('.well-known')) {
        return new Response(JSON.stringify(ENDPOINTS), { status: 200 })
      }
      return new Response(JSON.stringify({ access_token: 'AT', refresh_token: 'RT', expires_in: 300 }), { status: 200 })
    }))
    const tokens = await completeLogin(CFG, { code: 'CODE', state: 'ST' })
    expect(tokens.accessToken).toBe('AT')
    expect(tokens.refreshToken).toBe('RT')
    // the token call carried the verifier + code
    const tokenCall = calls.find((c) => c.url.endsWith('/token'))!
    const body = String(tokenCall.init!.body)
    expect(body).toContain('code_verifier=VERIFIER123')
    expect(body).toContain('grant_type=authorization_code')
    expect(body).toContain('code=CODE')
    // one-time material cleared
    expect(sessionStorage.getItem('oidc.pkce.verifier')).toBeNull()
  })
})
