import { test, expect } from '@playwright/test'
import { readFileSync } from 'fs'
import { resolve } from 'path'

// Real credentials from the live division's generated secrets (gitignored).
// Playwright runs from the ui/ dir, so the repo's infra/ is one level up.
function seedPassword(division: string): string {
  const p = resolve(process.cwd(), `../infra/generated/${division}/secrets.json`)
  return JSON.parse(readFileSync(p, 'utf8')).seed_user_password
}

const ALICE_PW = seedPassword('alpha')
const BOB_PW = seedPassword('beta')

// Drives the ACTUAL rendered React UI in a headless browser against the live divisions
// (via the Vite proxy) — not the API contract in isolation. Proves the customer-facing
// path: load → log in → ask → a real answer renders in the DOM.
test('alice logs in and a real answer renders in the UI (left pane)', async ({ page }) => {
  await page.goto('/')
  await expect(page).toHaveTitle(/Federated RAG/)

  // Left pane = Division Alpha (alice). Username is pre-filled.
  const username = page.locator('input[autocomplete="username"]').first()
  await expect(username).toHaveValue('alice')
  await page.locator('input[type="password"]').first().fill(ALICE_PW)
  await page.getByRole('button', { name: 'Login' }).first().click()

  // After login the chat composer appears.
  const chat = page.locator('textarea.chat-input').first()
  await expect(chat).toBeVisible({ timeout: 30_000 })

  // Ask a question alice is authorized for locally.
  await chat.fill('What is the data retention policy?')
  await page.locator('button.btn-send').first().click()

  // The query bubble shows immediately…
  await expect(page.locator('.bubble-user').first()).toContainText('data retention policy')

  // …and a real answer streams into the DOM (LLM can be slow on the free tier).
  const answer = page.locator('.bubble-agent').first()
  await expect(answer).toBeVisible({ timeout: 210_000 })
  await expect(answer).toContainText(/retention|ACME|years/i)

  // The task card reaches the Done state.
  await expect(page.locator('.badge-green').first()).toBeVisible()
})

// The federation differentiator: alice (Division Alpha) asks for data that lives on
// Division Beta and is authorized cross-division — the agent delegates over the signed
// /a2a transport and the peer's answer renders back in alice's pane.
test('alice gets a federated cross-division answer in the UI', async ({ page }) => {
  await page.goto('/')
  await page.locator('input[type="password"]').first().fill(ALICE_PW)
  await page.getByRole('button', { name: 'Login' }).first().click()

  const chat = page.locator('textarea.chat-input').first()
  await expect(chat).toBeVisible({ timeout: 30_000 })
  await chat.fill('What were the Q4 financial results and revenue?')
  await page.locator('button.btn-send').first().click()

  // The peer-sourced answer renders (Q4 revenue lives on Division Beta).
  const answer = page.locator('.bubble-agent').first()
  await expect(answer).toBeVisible({ timeout: 210_000 })
  await expect(answer).toContainText(/\$?48\.3|revenue|Q4/i)
  await expect(page.locator('.badge-green').first()).toBeVisible()
})

// The full human-in-the-loop governance story, rendered: alice requests data she is NOT
// cleared for -> her pane parks on "Awaiting approval" -> bob (the data owner) sees the
// request in HIS pane's inbox and approves -> alice's answer appears automatically.
test('approval flow: alice requests, bob approves in his inbox, alice gets the answer', async ({ page, request }) => {
  // SETUP (no UI for this): revoke alice's standing q4 grant so the request must go
  // through approval. Done via bob's owner-authenticated API token — mirrors an admin
  // resetting access; keeps the test self-contained and repeatable.
  const kc = await request.post('http://localhost:9102/realms/rag/protocol/openid-connect/token', {
    form: { grant_type: 'password', client_id: 'rag-ui', username: 'bob', password: BOB_PW },
  })
  const bobToken = (await kc.json()).access_token as string
  await request.post('http://127.0.0.1:9100/access/revoke', {
    headers: { Authorization: `Bearer ${bobToken}` },
    data: { user_email: 'alice@example.com', doc: 'q4_financial_results', home_division: 'alpha' },
  })

  await page.goto('/')
  const alicePane = page.locator('.user-pane').nth(0)
  const bobPane = page.locator('.user-pane').nth(1)

  // Log both users in (each pane independently).
  await alicePane.locator('input[type="password"]').fill(ALICE_PW)
  await alicePane.getByRole('button', { name: 'Login' }).click()
  await bobPane.locator('input[type="password"]').fill(BOB_PW)
  await bobPane.getByRole('button', { name: 'Login' }).click()

  // alice asks for the now-restricted Q4 data -> her task parks on approval.
  const aliceChat = alicePane.locator('textarea.chat-input')
  await expect(aliceChat).toBeVisible({ timeout: 30_000 })
  await aliceChat.fill('What were the Q4 financial results and revenue?')
  await alicePane.locator('button.btn-send').click()
  await expect(alicePane.locator('.badge-yellow')).toBeVisible({ timeout: 210_000 })  // ⏳ Awaiting approval

  // bob's inbox surfaces the request (polls every ~4s); approve every pending item so a
  // stale index entry (self-healed server-side on click) can't hide the real request.
  await expect(bobPane.locator('.approval-item .btn-approve').first()).toBeVisible({ timeout: 60_000 })
  for (let i = 0; i < 5; i++) {
    const buttons = bobPane.locator('.approval-item .btn-approve')
    const n = await buttons.count()
    if (n === 0) break
    await buttons.first().click()
    await bobPane.page().waitForTimeout(1500)  // let the decision POST + inbox refresh settle
  }

  // Back in alice's pane, the answer is DELIVERED automatically once the grant lands
  // and her client polls the outcome — no re-typing, no shared browser.
  const aliceAnswer = alicePane.locator('.bubble-agent').first()
  await expect(aliceAnswer).toContainText(/\$?48\.3|revenue|Q4/i, { timeout: 210_000 })
  await expect(alicePane.locator('.badge-green')).toBeVisible()
})
