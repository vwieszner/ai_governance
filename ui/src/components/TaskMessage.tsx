import type { NormalizedTask, TaskState } from '../types'

const STATE_BADGE: Record<TaskState, { label: string; cls: string }> = {
  submitted:        { label: 'Submitted',          cls: 'badge-grey'   },
  working:          { label: '⚙ Working…',         cls: 'badge-blue'   },
  'input-required': { label: '⏳ Awaiting approval', cls: 'badge-yellow' },
  completed:        { label: '✓ Done',              cls: 'badge-green'  },
  failed:           { label: '✕ Failed',            cls: 'badge-red'    },
  canceled:         { label: 'Canceled',            cls: 'badge-grey'   },
}

interface Props {
  task: NormalizedTask
}

export function TaskMessage({ task }: Props) {
  const badge = STATE_BADGE[task.state] ?? { label: task.state, cls: 'badge-grey' }

  return (
    <div className="task-card">
      <div className="task-query">
        <span className="bubble-user">{task.query}</span>
      </div>

      <div className="task-response">
        <span className={`badge ${badge.cls}`}>{badge.label}</span>

        {task.flow && (
          <span className="task-flow">flow: {task.flow}</span>
        )}

        {task.state === 'working' && task.statusMessage && (
          <p className="status-msg">{task.statusMessage}</p>
        )}

        {task.answer && (
          <p className="bubble-agent">{task.answer}</p>
        )}

        {task.state === 'input-required' && !task.answer && (
          <>
            {task.statusMessage && <p className="bubble-agent">{task.statusMessage}</p>}
            <p className="status-msg muted">⏳ Waiting for the data owner's decision — the answer will appear here automatically once approved.</p>
          </>
        )}

        {task.peerTaskId && (
          <p className="peer-note">↳ delegated to peer · task {task.peerTaskId}</p>
        )}

        {task.state === 'failed' && task.statusMessage && (
          <p className="error-msg">{task.statusMessage}</p>
        )}
      </div>
    </div>
  )
}
