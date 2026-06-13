# AGT Federated RAG — UI

## Overview

A React + Vite split-screen interface over **two divisions** of the AGT federated-RAG system.
The left pane is **alice @ Division Alpha**, the right pane **bob @ Division Beta** — both speak
the *same* AGT contract (`POST /query`, status/result/done SSE), differing only in which
physically-isolated division they hit. Both stream answers in real time; a slide-up **Monitor**
panel captures every agent event (cross-division peer calls, approval handshakes, status
transitions) so you can watch the governance flow live. The owner pane shows an **approval
inbox**; an approved requester's answer is delivered back automatically.

> This replaced an earlier "two different backends (cluster-a/cluster-b on 8000/8002)" design.
> There is one codebase (`agt-federated-rag/`) run as multiple divisions; both panes are AGT.

## Prerequisites

| Requirement | Notes |
|---|---|
| Node.js 18+ | `node -v` |
| Two divisions running | alpha agent `:9000`, beta agent `:9100` (via `scripts/bootstrap.ps1` or `clusters.ps1 start all`) |
| Keycloak per division | realm `rag`, client `rag-ui`, users `alice`/`bob` — provisioned by onboarding |

## Quick start

```bash
cp .env.example .env.prod      # then set NVIDIA_API_KEY; defaults already point at alpha/beta
npm install
npm run start                  # vite --mode prod -> http://localhost:5173
```

Logins: alice (alpha) / bob (beta); passwords in `infra/generated/<div>/secrets.json`
(`seed_user_password`). Run one throwaway query per pane first to warm the LLM.

## Configuration (`.env.prod`, consumed by `vite.config.ts`)

The browser only talks to the Vite origin (`:5173`), which **proxies** to the divisions, so API
hosts/keys are never in the browser bundle. Variables **without** `VITE_` are proxy config only;
`VITE_`-prefixed ones reach the browser.

| Var | Default | Meaning |
|---|---|---|
| `AGT_A_URL` / `AGT_B_URL` | `127.0.0.1:9000` / `:9100` | division agent API targets |
| `KEYCLOAK_A_URL` / `_B_URL` | `localhost:9002` / `:9102` | division IdP (MUST be `localhost` — Keycloak reflects the request host into the token `iss`, which the agent validates) |
| `REALM_A` / `REALM_B` | `rag` | OIDC realm |
| `VITE_AUTH_MODE` | `password` | `password` = the bundled two-pane demo; `pkce` = production OIDC Auth-Code + PKCE SSO redirect (set `VITE_OIDC_*`) |
| `NVIDIA_API_KEY`, `NVIDIA_BASE_URL`, `VITE_NVIDIA_MODEL` | — | LLM proxy (key injected server-side) |
| `VITE_CLUSTER_A_LABEL` / `_B_LABEL` | Division Alpha/Beta | pane headers |

## Auth modes

- **bff (production, recommended):** `VITE_AUTH_MODE=bff`. One division per browser session.
  Login redirects to the agent's `/bff/*` endpoints which do the OIDC Auth-Code + PKCE
  exchange **server-side**; the browser holds **only an `HttpOnly` session cookie** — no
  access/refresh token ever reaches JS (XSS can't steal it). Server-side silent refresh,
  login-CSRF state binding, CSRF double-submit. `src/api/session.ts` + `BffPane`. Each user
  logs in from their own browser; open the other division separately. Backend: `api/bff.py`.
- **password:** Keycloak password grant, two panes in one tab; tokens in React memory.
- **pkce:** `src/api/oidc.ts` — Auth-Code + PKCE in the SPA (tokens in the browser; weaker
  than bff, kept for reference).

## Tests

```bash
npm test        # Vitest unit: auth (password grant) + oidc (PKCE) + SSE normalization
npm run e2e     # Playwright (real browser, live divisions): local answer, federated answer,
                # and the full approval flow (park -> bob approves in inbox -> answer delivered)
```
`npm run e2e` needs the UI dev server (`npm run start`) and the divisions up.

## How it maps to the backend

- `src/api/auth.ts` — Keycloak password grant; `src/api/oidc.ts` — PKCE.
- `src/api/rag.ts` — `POST /query` + status/result/done SSE; requester-side approval polling of
  `GET /tasks/{id}/result` (uses the **server's** task id from the result event).
- `src/components/` — `UserPane`, `LoginForm`, `ChatArea`, `TaskMessage`, `ApprovalInbox`, `MonitorPanel`.
