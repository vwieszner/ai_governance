import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const agtAUrl      = env.AGT_A_URL       || 'http://localhost:8010'
  const agtBUrl      = env.AGT_B_URL       || 'http://localhost:8012'
  const keycloakAUrl = env.KEYCLOAK_A_URL  || 'http://localhost:8087'
  const keycloakBUrl = env.KEYCLOAK_B_URL  || 'http://localhost:8087'
  // Keycloak realm for OIDC. Authentication is always against a real Keycloak.
  const realmA       = env.REALM_A || 'rag'
  const realmB       = env.REALM_B || 'rag'
  const nvidiaBaseUrl = env.NVIDIA_BASE_URL || 'https://integrate.api.nvidia.com/v1'
  const nvidiaKey     = env.NVIDIA_API_KEY  || process.env.NVIDIA_API_KEY || ''

  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        // BFF (production browser auth) — same-origin path to the PRIMARY division's agent,
        // NOT rewritten (so /bff/login -> agent /bff/login). The HttpOnly session cookie is
        // set on this (5173) origin. One browser session = one division (multi-user model).
        '/bff': {
          target: agtAUrl,
          changeOrigin: true,
        },
        '/api/agt-a': {
          target: agtAUrl,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/agt-a/, ''),
        },
        '/api/agt-b': {
          target: agtBUrl,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/agt-b/, ''),
        },
        '/auth/a': {
          target: keycloakAUrl,
          changeOrigin: true,
          // /auth/a/token → {keycloak}/realms/{realm}/protocol/openid-connect/token
          rewrite: (path) =>
            path.replace(/^\/auth\/a/, `/realms/${realmA}/protocol/openid-connect`),
        },
        // LLM proxy — any OpenAI-compatible endpoint, configured via NVIDIA_BASE_URL
        // Authorization injected server-side; key never appears in browser bundle
        '/nvidia': {
          target: nvidiaBaseUrl,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/nvidia/, ''),
          headers: nvidiaKey ? { Authorization: `Bearer ${nvidiaKey}` } : {},
        },
        '/auth/b': {
          target: keycloakBUrl,
          changeOrigin: true,
          rewrite: (path) =>
            path.replace(/^\/auth\/b/, `/realms/${realmB}/protocol/openid-connect`),
        },
      },
    },
  }
})
