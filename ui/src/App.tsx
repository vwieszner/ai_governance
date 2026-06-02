import { Fragment, useState, useCallback } from 'react'
import { UserPane } from './components/UserPane'
import { MonitorPanel } from './components/MonitorPanel'
import type { AgentEvent } from './types'
import { CLUSTERS } from './types'

export default function App() {
  const [events, setEvents] = useState<AgentEvent[]>([])
  const [monitorOpen, setMonitorOpen] = useState(false)

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

      <main className={`app-main ${monitorOpen ? 'main-monitor-open' : ''}`}>
        {CLUSTERS.map((cluster, i) => (
          <Fragment key={cluster.id}>
            {i > 0 && <div className="pane-divider" />}
            <UserPane cluster={cluster} onEvent={addEvent} />
          </Fragment>
        ))}
      </main>

      <MonitorPanel
        events={events}
        isOpen={monitorOpen}
        onClose={() => setMonitorOpen(false)}
      />
    </div>
  )
}
