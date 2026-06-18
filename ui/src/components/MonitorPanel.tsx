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

// N-capable division coloring: hash the division id into one of a fixed palette of
// classes (ev-division-0…N). No hardcoded two-division assumption.
const DIVISION_COLOR_COUNT = 6
function divisionColorClass(divisionId: string): string {
  let h = 0
  for (let i = 0; i < divisionId.length; i++) h = (h * 31 + divisionId.charCodeAt(i)) | 0
  return `ev-division-${Math.abs(h) % DIVISION_COLOR_COUNT}`
}

// ── FR-3.4: observable inter-agent conversation ───────────────────────────────
//
// When the backend DELEGATES a query to a peer division it prepends a structured,
// machine-parseable marker to the status it streams back (agent/nodes.py
// `_delegation_marker`):
//
//   [agt:delegated division=<id> cap=<capability> via=<discovered|configured-fallback> negotiated=<0|1>]
//
// We PARSE that marker rather than inferring the cross-division hop from arbitrary
// status prose. The parsed fields drive an explicit "delegated → <peer division>"
// chip (with the discovered capability and whether the peer was negotiated vs. the
// configured fallback), and the human prose is shown with the marker stripped. So the
// monitor surfaces the ACTUAL discover → negotiate → delegate events, keyed on a
// real signal from the agent, not keyword-sniffing.
interface Delegation {
  division: string
  capability: string
  via: string          // "discovered" | "configured-fallback"
  negotiated: boolean
}

// Parse ONLY the first `]`-terminated marker token (A4 hardening): the capture groups
// exclude `[`/`]`/whitespace and `\]` matches the FIRST closing bracket, so a peer-supplied
// division/capability that smuggles a `]` (closing the marker early) or a `[` (opening a
// forged second marker) cannot make us render a spoofed "discovered + negotiated" event.
// The backend sanitises these fields too (agent/nodes.py `_sanitize_marker_field`); this
// is the defence-in-depth UI half of that fix. The marker is anchored to the start so only
// the agent's own leading marker is ever interpreted as a delegation signal.
const DELEGATION_RE =
  /^\[agt:delegated\s+division=([^\s[\]]+)\s+cap=([^\s[\]]*)\s+via=([^\s[\]]+)\s+negotiated=([01])\]\s*/

function parseDelegation(message: string): { delegation: Delegation | null; text: string } {
  const m = DELEGATION_RE.exec(message)
  if (!m) return { delegation: null, text: message }
  const delegation: Delegation = {
    division: m[1],
    capability: m[2] || '',
    via: m[3],
    negotiated: m[4] === '1',
  }
  // Strip the marker so the user-facing prose reads cleanly.
  const text = message.replace(DELEGATION_RE, '').trim()
  return { delegation, text }
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
            const divisionCls = divisionColorClass(ev.division)
            const { delegation, text } = parseDelegation(ev.message)
            return (
              <div key={ev.id} className={`monitor-event ${meta.cls}`}>
                <span className="ev-time">{fmtTime(ev.timestamp)}</span>
                <span className={`ev-division ${divisionCls}`}>{ev.division}</span>
                <span className="ev-user">{ev.user}</span>
                <span className="ev-icon">{meta.icon}</span>
                {/* Chip + prose share the final grid cell so the delegation badge never
                    shifts the fixed-column layout (no extra grid track, no CSS change).
                    Inline flex keeps the existing .ev-msg truncation working when nested. */}
                <span style={{ display: 'flex', alignItems: 'baseline', gap: 8, minWidth: 0 }}>
                  {delegation && (
                    <span
                      className={`ev-division ${divisionColorClass(delegation.division)}`}
                      style={{ fontSize: 11, whiteSpace: 'nowrap', flex: '0 0 auto' }}
                      title={
                        `${delegation.via === 'discovered' ? 'Discovered' : 'Configured'} peer` +
                        `${delegation.capability ? ` for "${delegation.capability}"` : ''}` +
                        `${delegation.negotiated ? ' · negotiated' : ''}`
                      }
                    >
                      {delegation.via === 'discovered' ? '⇲ discovered' : '⇲ delegated'}
                      {' → '}{delegation.division || 'peer'}
                      {delegation.capability ? ` · ${delegation.capability}` : ''}
                      {delegation.negotiated ? ' ✓' : ''}
                    </span>
                  )}
                  <span className="ev-msg" style={{ minWidth: 0 }} title={text || ev.message}>
                    {text || ev.message}
                  </span>
                </span>
              </div>
            )
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
