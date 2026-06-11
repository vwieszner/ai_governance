import { defineConfig } from '@playwright/test'

// E2E against the running dev server (npm run start -> http://localhost:5173, which
// proxies to the live divisions alpha:9000 / beta:9100). The LLM (NVIDIA free tier) can
// be slow, so timeouts are generous.
export default defineConfig({
  testDir: './e2e',
  timeout: 240_000,
  expect: { timeout: 210_000 },
  fullyParallel: false,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:5173',
    headless: true,
    actionTimeout: 30_000,
  },
})
