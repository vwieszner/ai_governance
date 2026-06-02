import { describe, it, expect, vi, afterEach } from 'vitest'
import { getToken, AuthError } from './auth'

// Helper: build a minimal Response-like object for fetch mocks
function makeResponse(
  status: number,
  body: unknown,
): Response {
  const jsonStr = JSON.stringify(body)
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => JSON.parse(jsonStr),
    text: async () => jsonStr,
  } as unknown as Response
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('getToken', () => {
  it('returns access_token on successful login', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeResponse(200, { access_token: 'tok123' })))

    const token = await getToken('/auth/a', 'rag-ui', 'alice', 'secret')

    expect(token).toBe('tok123')

    const fetchMock = vi.mocked(fetch)
    expect(fetchMock).toHaveBeenCalledOnce()
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/auth/a/token')
    expect(init.method).toBe('POST')
    expect((init.headers as Record<string, string>)['Content-Type']).toBe(
      'application/x-www-form-urlencoded',
    )
    // Body should contain all required form fields
    const bodyStr = init.body as string
    expect(bodyStr).toContain('grant_type=password')
    expect(bodyStr).toContain('client_id=rag-ui')
    expect(bodyStr).toContain('username=alice')
  })

  it('throws AuthError with server message on 401', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(makeResponse(401, { error: 'invalid_credentials' })),
    )

    await expect(getToken('/auth/a', 'rag-ui', 'alice', 'wrong')).rejects.toThrow(AuthError)
    await expect(getToken('/auth/a', 'rag-ui', 'alice', 'wrong')).rejects.toThrow(
      'invalid_credentials',
    )
  })

  it('throws AuthError when access_token is missing from 200 response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeResponse(200, {})))

    await expect(getToken('/auth/a', 'rag-ui', 'alice', 'secret')).rejects.toThrow(AuthError)
    await expect(getToken('/auth/a', 'rag-ui', 'alice', 'secret')).rejects.toThrow(
      'No access_token in response',
    )
  })

  it('throws AuthError with status code in message when body is not JSON', async () => {
    const nonJsonResponse = {
      ok: false,
      status: 403,
      text: async () => 'Forbidden',
      json: async () => { throw new Error('not json') },
    } as unknown as Response
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(nonJsonResponse))

    await expect(getToken('/auth/b', 'rag-ui', 'bob', 'bad')).rejects.toThrow(AuthError)
    await expect(getToken('/auth/b', 'rag-ui', 'bob', 'bad')).rejects.toThrow('Auth failed (403)')
  })
})
