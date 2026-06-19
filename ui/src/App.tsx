import { useState, useCallback, useEffect } from 'react'
import { UserPane } from './components/UserPane'
import { BffPane } from './components/BffPane'
import { MonitorPanel } from './components/MonitorPanel'
import type { AgentEvent } from './types'
import { DIVISIONS, PRIMARY_DIVISION } from './types'
import { readEnvConfig, parseCallback, completeLogin } from './api/oidc'
import { bffEnabled } from './api/session'

export default function App() {
  const [events, setEvents] = useState<AgentEvent[]>([])
  const [monitorOpen, setMonitorOpen] = useState(false)
  // Production auth (BFF): one division per browser session, no token in the browser.
  const bff = bffEnabled()
  // One division per browser, chosen by ?cluster=<id> (e.g. ?cluster=gamma). No split pane.
  const clusterId = new URLSearchParams(window.location.search).get('cluster')
  const selected = clusterId ? DIVISIONS.find((d) => d.id === clusterId) : undefined
  // TODO(inbox): when the /inbox retrieval endpoint lands, wire per-division offline
  // delivery off Division.apiBase here. Left for the inbox-backend work.

  // PKCE/SSO: if we returned from the IdP with ?code=&state=, exchange it for tokens.
  // (Additive — does nothing in the default password-grant demo mode.)
  const [oidcError, setOidcError] = useState('')
  useEffect(() => {
    const cfg = readEnvConfig()
    if (!cfg) return
    const cb = parseCallback(window.location.search)
    if (!cb) return
    completeLogin(cfg, cb)
      .then((tokens) => {
        // Hand off to the OIDC session store and clean the code/state from the URL.
        sessionStorage.setItem('oidc.tokens', JSON.stringify(tokens))
        window.history.replaceState({}, '', window.location.pathname)
      })
      .catch((e) => setOidcError(String(e)))
  }, [])

  const addEvent = useCallback((ev: AgentEvent) => {
    setEvents((prev) => [...prev, ev])
  }, [])

  return (
    <div className="app">
      <header className="app-header">
        <span className="app-title">Federated RAG</span>
        <button
          className={`btn-monitor ${monitorOpen ? 'btn-monitor-active' : ''}`}
          onClick={() => setMonitorOpen((o) => !o)}
        >
          Monitor {monitorOpen ? '⬇' : '⬆'}
          {events.length > 0 && (
            <span className="monitor-badge">{events.length}</span>
          )}
        </button>
      </header>

      {oidcError && <p className="chat-error" style={{ margin: '8px 16px' }}>SSO error: {oidcError}</p>}

      <main className={`app-main ${monitorOpen ? 'main-monitor-open' : ''}`}>
        {bff ? (
          // BFF mode: ONE division per browser session (the production multi-user model —
          // open another division in a separate browser). No token ever in the browser.
          <BffPane division={PRIMARY_DIVISION} onEvent={addEvent} />
        ) : selected ? (
          // ONE division per browser, chosen by ?cluster=<id>. Open another division in
          // another browser/window to present the federated, multi-department setup.
          <UserPane division={selected} onEvent={addEvent} />
        ) : (
          // No ?cluster= → a picker: each configured division opens in this browser.
          <div className="division-picker">
            <h2>Pick a division to log in as</h2>
            <p>Open a different division in each browser/window to present the federation.</p>
            <div className="division-grid">
              {DIVISIONS.map((d) => (
                <a key={d.id} className="division-card" href={`?cluster=${d.id}`}>
                  <span className="division-card-label">{d.label}</span>
                  <span className="division-card-id">?cluster={d.id}</span>
                </a>
              ))}
            </div>
          </div>
        )}
      </main>

      <MonitorPanel
        events={events}
        isOpen={monitorOpen}
        onClose={() => setMonitorOpen(false)}
      />
    </div>
  )
}
