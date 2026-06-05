import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const clusterAUrl  = env.CLUSTER_A_URL   || 'http://localhost:8000'
  const clusterBUrl  = env.CLUSTER_B_URL   || 'http://localhost:8002'
  const agtAUrl      = env.AGT_A_URL       || 'http://localhost:8010'
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
        // NOTE: more-specific prefixes must come first — /api/agt-a before /api/a
        // otherwise Vite matches /api/a first and strips only that prefix, leaving
        // "gt-a/..." which the AGT backend doesn't recognise.
        '/api/agt-a': {
          target: agtAUrl,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/agt-a/, ''),
        },
        '/api/a': {
          target: clusterAUrl,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/a/, ''),
        },
        '/api/b': {
          target: clusterBUrl,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/b/, ''),
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
