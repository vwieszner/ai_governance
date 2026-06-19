import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// ── Single source of truth for the divisions on screen ───────────────────────
// divisions.config.json drives BOTH the UI division list AND the Vite proxy routes.
// To present another cluster/agent: add ONE entry here (id, label, agentPort,
// keycloakPort) + make sure that agent is reachable on those localhost ports
// (Compose runs locally; for k8s run `kubectl -n agt-div-<id> port-forward svc/agent
// <agentPort>:8000` and `svc/keycloak <keycloakPort>:8080`). No code change.
const HERE = dirname(fileURLToPath(import.meta.url))
type Div = { id: string; label: string; defaultUser?: string; agentPort: number; keycloakPort: number; realm?: string }
const DIVS: Div[] = JSON.parse(readFileSync(resolve(HERE, 'divisions.config.json'), 'utf-8'))

export default defineConfig(() => {
  const nvidiaBaseUrl = process.env.NVIDIA_BASE_URL || 'https://integrate.api.nvidia.com/v1'
  const nvidiaKey = process.env.NVIDIA_API_KEY || ''

  // Generate /api/agt-<id> -> that division's agent, and /auth/<id> -> its Keycloak,
  // for every configured division. One browser opens ?cluster=<id> -> one division.
  const proxy: Record<string, unknown> = {
    '/nvidia': {
      target: nvidiaBaseUrl, changeOrigin: true,
      rewrite: (p: string) => p.replace(/^\/nvidia/, ''),
      headers: nvidiaKey ? { Authorization: `Bearer ${nvidiaKey}` } : {},
    },
  }
  for (const d of DIVS) {
    proxy[`/api/agt-${d.id}`] = {
      target: `http://localhost:${d.agentPort}`, changeOrigin: true,
      rewrite: (p: string) => p.replace(new RegExp(`^/api/agt-${d.id}`), ''),
    }
    proxy[`/auth/${d.id}`] = {
      target: `http://localhost:${d.keycloakPort}`, changeOrigin: true,
      rewrite: (p: string) =>
        p.replace(new RegExp(`^/auth/${d.id}`), `/realms/${d.realm || 'rag'}/protocol/openid-connect`),
    }
  }
  // BFF passthrough to the first division (production single-session path).
  proxy['/bff'] = { target: `http://localhost:${DIVS[0].agentPort}`, changeOrigin: true }

  // Hand the app the division list (id/label/defaultUser + the proxy paths). types.ts
  // parses VITE_DIVISIONS; we inject it from the same config so there's ONE source.
  const viteDivisions = JSON.stringify(DIVS.map((d) => ({
    id: d.id, label: d.label, defaultUser: d.defaultUser ?? '',
    apiBase: `/api/agt-${d.id}`, authBase: `/auth/${d.id}`,
  })))

  return {
    plugins: [react()],
    define: { 'import.meta.env.VITE_DIVISIONS': JSON.stringify(viteDivisions) },
    server: { port: 5173, proxy },
  }
})
