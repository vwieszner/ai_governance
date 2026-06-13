// BFF session client — production auth. The browser holds NO token; it relies on the
// HttpOnly session cookie set by the BFF. This module only reads identity + the CSRF token
// and drives login/logout redirects.

export interface BffSession {
  authenticated: boolean
  user?: string
  groups?: string[]
  csrf_token?: string
}

export function bffEnabled(): boolean {
  return (import.meta.env.VITE_AUTH_MODE ?? 'password') === 'bff'
}

export async function getSession(): Promise<BffSession> {
  const res = await fetch('/bff/session', { credentials: 'include' })
  if (!res.ok) return { authenticated: false }
  return (await res.json()) as BffSession
}

/** Redirect the whole tab to the BFF login (which redirects to the IdP). */
export function login(): void {
  window.location.assign('/bff/login')
}

export async function logout(csrf: string): Promise<void> {
  await fetch('/bff/logout', {
    method: 'POST',
    credentials: 'include',
    headers: csrf ? { 'X-CSRF-Token': csrf } : {},
  })
  window.location.reload()
}
