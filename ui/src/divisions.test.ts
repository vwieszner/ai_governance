import { describe, it, expect } from 'vitest'
import { parseDivisionsEnv } from './types'

// The N-division config knob (FR-2.4): VITE_DIVISIONS drives the configurable, N-capable
// division list. DEFAULTS (clientId/protocol) fill in; apiBase + authBase are required.
describe('parseDivisionsEnv', () => {
  it('returns null for an unset/blank value (so the bundled default is used)', () => {
    expect(parseDivisionsEnv(undefined)).toBeNull()
    expect(parseDivisionsEnv('')).toBeNull()
    expect(parseDivisionsEnv('   ')).toBeNull()
  })

  it('parses an N-division JSON array, filling defaults', () => {
    const divs = parseDivisionsEnv(
      '[{"id":"alpha","label":"Division Alpha","apiBase":"/api/agt-a","authBase":"/auth/a"},' +
        '{"id":"beta","apiBase":"/api/agt-b","authBase":"/auth/b"},' +
        '{"id":"gamma","label":"Division Gamma","apiBase":"/api/agt-c","authBase":"/auth/c"}]',
    )
    expect(divs).not.toBeNull()
    expect(divs!).toHaveLength(3) // not capped at two — N-capable
    expect(divs![0]).toMatchObject({
      id: 'alpha',
      label: 'Division Alpha',
      apiBase: '/api/agt-a',
      authBase: '/auth/a',
      clientId: 'rag-ui', // default
      protocol: 'agt', // default
    })
    // label defaults to id when omitted
    expect(divs![1].label).toBe('beta')
    expect(divs![2].id).toBe('gamma')
  })

  it('rejects entries missing apiBase/authBase', () => {
    expect(() => parseDivisionsEnv('[{"id":"alpha","apiBase":"/api/agt-a"}]')).toThrow(/authBase/)
    expect(() => parseDivisionsEnv('[{"id":"beta","authBase":"/auth/b"}]')).toThrow(/apiBase/)
  })

  it('rejects malformed JSON and non-array / empty input', () => {
    expect(() => parseDivisionsEnv('{not json')).toThrow(/valid JSON/)
    expect(() => parseDivisionsEnv('{"id":"alpha"}')).toThrow(/non-empty JSON array/)
    expect(() => parseDivisionsEnv('[]')).toThrow(/non-empty JSON array/)
  })
})
