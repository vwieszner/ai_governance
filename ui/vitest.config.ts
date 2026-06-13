import { defineConfig } from 'vitest/config'

// Unit tests only (vitest). The Playwright e2e suite under e2e/ is run separately via
// `npm run e2e` and must NOT be collected by vitest (it calls Playwright's test()).
export default defineConfig({
  test: {
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
  },
})
