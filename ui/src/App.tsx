import { Fragment, useState, useCallback, useEffect } from 'react'
import { UserPane } from './components/UserPane'
import { BffPane } from './components/BffPane'
import { MonitorPanel } from './components/MonitorPanel'
import type { AgentEvent } from './types'
import { CLUSTERS, CLUSTER_AGT_A } from './types'
import { readEnvConfig, parseCallback, completeLogin } from './api/oidc'
import { bffEnabled } from './api/session'

export default function App() {
  const [events, setEvents] = useState<AgentEvent[]>([])
  const [monitorOpen, setMonitorOpen] = useState(false)
  // Production auth (BFF): one division per browser session, no token in the browser.
  const bff = bffEnabled()

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
          // open the other division in a separate browser). No token ever in the browser.
          <BffPane cluster={CLUSTER_AGT_A} onEvent={addEvent} />
        ) : (
          CLUSTERS.map((cluster, i) => (
            <Fragment key={cluster.id}>
              {i > 0 && <div className="pane-divider" />}
              <UserPane cluster={cluster} onEvent={addEvent} />
            </Fragment>
          ))
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
