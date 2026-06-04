export class AuthError extends Error {}

export interface AuthTokens {
  accessToken: string
  refreshToken: string
  expiresIn: number
}

async function parseTokenResponse(res: Response): Promise<AuthTokens> {
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    let detail = `Auth failed (${res.status})`
    try {
      const json = JSON.parse(text)
      if (json.error_description) detail = json.error_description
      else if (json.error) detail = json.error
    } catch { /* not JSON */ }
    throw new AuthError(detail)
  }

  const json = await res.json()
  if (!json.access_token) throw new AuthError('No access_token in response')
  return {
    accessToken: json.access_token as string,
    refreshToken: (json.refresh_token as string) ?? '',
    expiresIn: (json.expires_in as number) ?? 0,
  }
}

export async function getToken(
  authBase: string,
  clientId: string,
  username: string,
  password: string,
): Promise<AuthTokens> {
  const body = new URLSearchParams({
    grant_type: 'password',
    client_id: clientId,
    username,
    password,
  })

  const res = await fetch(`${authBase}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })

  return parseTokenResponse(res)
}

export async function refreshAccessToken(
  authBase: string,
  clientId: string,
  refreshToken: string,
): Promise<AuthTokens> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: clientId,
    refresh_token: refreshToken,
  })

  const res = await fetch(`${authBase}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })

  return parseTokenResponse(res)
}
