# Federated RAG UI

## Overview

This React + Vite application provides a split-screen interface for interacting with two federated RAG backends simultaneously. The left pane authenticates as **alice** against `federated-rag` (cluster-a, A2A protocol) and the right pane authenticates as **bob** against `agt-federated-rag` (cluster-b, AGT/DID identity). Both panes stream task updates in real time over SSE. A slide-up **Monitor** panel captures every agent-to-agent event emitted by either cluster so you can observe cross-cluster peer calls, approval handshakes, and status transitions in one place.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Node.js 18+ | `node -v` to check |
| `federated-rag` running | cluster-a, default port 8000 |
| `agt-federated-rag` running | cluster-b, default port 8002 |
| Keycloak configured | realm `rag`, client `rag-ui`, users `alice` and `bob` created |

Both backends must have `CORSMiddleware` enabled (see [Note on CORS](#note-on-cors)).

---

## Quick Start

```bash
# 1. Copy the example env file and edit it for your environment
cp .env.example .env

# 2. Install dependencies
npm install

# 3. Start the dev server
npm run dev
```

Open **http://localhost:5173** in your browser.

---

## Environment Variables

These variables configure the Vite dev-server proxy. They are **not** embedded in the browser bundle.

Copy `.env.example` to `.env` and adjust the values to match your deployment.

| Variable | Default | Description |
|---|---|---|
| `CLUSTER_A_URL` | `http://localhost:8000` | Base URL of the `federated-rag` (cluster-a) FastAPI server |
| `CLUSTER_B_URL` | `http://localhost:8002` | Base URL of the `agt-federated-rag` (cluster-b) FastAPI server |
| `KEYCLOAK_A_URL` | `http://localhost:8080` | Keycloak server root used to authenticate alice (no realm or path suffix) |
| `KEYCLOAK_B_URL` | `http://localhost:8080` | Keycloak server root used to authenticate bob (no realm or path suffix) |
| `REALM_A` | `rag` | Keycloak realm for cluster-a |
| `REALM_B` | `rag` | Keycloak realm for cluster-b |

---

## How to Use

1. **Log in** — on the left pane enter `alice`'s password and click **Login**; on the right pane enter `bob`'s password and click **Login**. Each pane performs an OIDC password-grant flow against its configured Keycloak realm and stores the bearer token in component state.

2. **Submit a query** — type a question in either pane's text field and press **Send**. The pane displays the task state (`submitted → working → completed`) and streams the answer as it arrives over SSE.

3. **Watch the Monitor** — click the **Monitor** button in the header to slide up the event panel. Every `query_sent`, `agent_working`, `peer_call`, `approval_needed`, `completed`, and `failed` event from both clusters appears here in chronological order, colour-coded by cluster. Click **Monitor** again (or the close button) to hide the panel.

4. **Peer calls** — when cluster-a delegates to cluster-b (or vice versa) you will see a `peer_call` event in the Monitor. The originating pane also shows a `peerTaskId` link so you can correlate tasks across clusters.

---

## Production Build

```bash
npm run build
```

Output goes to `dist/`. Serve it with any static file host:

```bash
# Quick check with Vite's preview server
npm run preview

# Or copy dist/ into a FastAPI app
# In your FastAPI main.py:
# from fastapi.staticfiles import StaticFiles
# app.mount("/", StaticFiles(directory="ui/dist", html=True), name="ui")
```

When serving behind FastAPI or nginx, make sure the `/api/a`, `/api/b`, `/auth/a`, and `/auth/b` path prefixes are reverse-proxied to the correct backend and Keycloak hosts — the same targets configured in `.env` for the Vite dev proxy.

---

## Note on CORS

Both backends are configured with `CORSMiddleware(allow_origins=["*"])` for local development. Before deploying to production, restrict origins to the exact UI URL:

```python
# federated-rag / agt-federated-rag main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-ui-domain.example.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Similarly, update the Keycloak client's **Valid Redirect URIs** and **Web Origins** to match the production UI origin.
