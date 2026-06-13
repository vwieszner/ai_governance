import { test, expect } from '@playwright/test'
import { readFileSync } from 'fs'
import { resolve } from 'path'

// Production BFF auth, end-to-end in a real browser: redirect to Keycloak, log in, return,
// and prove (a) the user is authenticated via the HttpOnly cookie, (b) a query works, and
// (c) NO token is in browser storage — the whole point of the BFF pattern.
// Requires the UI dev server running with VITE_AUTH_MODE=bff and division alpha up.
function seedPassword(division: string): string {
  const p = resolve(process.cwd(), `../infra/generated/${division}/secrets.json`)
  return JSON.parse(readFileSync(p, 'utf8')).seed_user_password
}
const ALICE_PW = seedPassword('alpha')

// Only runs against a BFF-mode server (VITE_AUTH_MODE=bff). Set E2E_BFF=1 to enable, so the
// default `npm run e2e` (password mode, two-pane) isn't broken by this single-pane SSO test.
test.skip(process.env.E2E_BFF !== '1', 'BFF e2e: run with E2E_BFF=1 against a bff-mode server')

test('BFF: SSO login via cookie, query works, NO token in browser storage', async ({ page }) => {
  await page.goto('/')

  // BffPane (unauthenticated) shows the SSO button → click → redirected to Keycloak.
  await page.getByRole('button', { name: /Sign in with SSO/i }).click()
  await page.waitForURL(/localhost:9002\/realms\/rag/, { timeout: 30_000 })

  // Keycloak login form.
  await page.locator('#username').fill('alice')
  await page.locator('#password').fill(ALICE_PW)
  await page.locator('#kc-login, input[type="submit"]').first().click()

  // Back on the app, authenticated (cookie set), chat composer visible.
  await page.waitForURL(/localhost:5173/, { timeout: 30_000 })
  const chat = page.locator('textarea.chat-input')
  await expect(chat).toBeVisible({ timeout: 30_000 })

  // THE point of BFF: no access/refresh token anywhere JavaScript can read.
  const storage = await page.evaluate(() => ({
    session: JSON.stringify(sessionStorage),
    local: JSON.stringify(localStorage),
  }))
  expect(storage.session).not.toMatch(/eyJ|access_token|refresh_token/)  // no JWT/token shapes
  expect(storage.local).not.toMatch(/eyJ|access_token|refresh_token/)

  // And a real query works (cookie -> server-side token injection).
  await chat.fill('What is the data retention policy?')
  await page.locator('button.btn-send').click()
  const answer = page.locator('.bubble-agent').first()
  await expect(answer).toBeVisible({ timeout: 210_000 })
  await expect(answer).toContainText(/retention|ACME|years/i)
})
