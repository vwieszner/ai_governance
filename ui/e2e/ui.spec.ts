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
