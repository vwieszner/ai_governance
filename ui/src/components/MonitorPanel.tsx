import { useEffect, useRef } from 'react'
import type { AgentEvent, EventKind } from '../types'

const KIND_META: Record<EventKind, { icon: string; cls: string }> = {
  query_sent:      { icon: '→', cls: 'ev-sent'     },
  agent_working:   { icon: '⚙', cls: 'ev-working'  },
  peer_call:       { icon: '⇄', cls: 'ev-peer'     },
  approval_needed: { icon: '⏳', cls: 'ev-approval' },
  completed:       { icon: '✓', cls: 'ev-done'     },
  failed:          { icon: '✕', cls: 'ev-failed'   },
  raw_update:      { icon: '·', cls: 'ev-raw'      },
}

function fmtTime(d: Date): string {
  return d.toLocaleTimeString('en-US', { hour12: false })
}

interface Props {
  events: AgentEvent[]
  isOpen: boolean
  onClose: () => void
}

export function MonitorPanel({ events, isOpen, onClose }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (isOpen) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events, isOpen])

  return (
    <div className={`monitor-panel ${isOpen ? 'monitor-open' : ''}`}>
      <div className="monitor-header">
        <span>Agent Communications</span>
        <button className="btn-close" onClick={onClose} title="Close">✕</button>
      </div>

      <div className="monitor-body">
        {events.length === 0 ? (
          <p className="monitor-empty">
            No events yet — submit a query to watch agent communications in real time.
          </p>
        ) : (
          events.map((ev) => {
            const meta = KIND_META[ev.kind]
            const clusterCls = ev.cluster === 'cluster-a' ? 'ev-cluster-a' : ev.cluster === 'cluster-agt-a' ? 'ev-cluster-agt-a' : 'ev-cluster-b'
            return (
              <div key={ev.id} className={`monitor-event ${meta.cls}`}>
                <span className="ev-time">{fmtTime(ev.timestamp)}</span>
                <span className={`ev-cluster ${clusterCls}`}>{ev.cluster}</span>
                <span className="ev-user">{ev.user}</span>
                <span className="ev-icon">{meta.icon}</span>
                <span className="ev-msg" title={ev.message}>{ev.message}</span>
              </div>
            )
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
