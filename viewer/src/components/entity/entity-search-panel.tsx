import { useState } from 'react'
import type { LiveClient } from '../../lib/live-client'
import type { EntitySearchMatch, EntitySearchResult } from '../../types/entity'

interface EntitySearchPanelProps {
  client: LiveClient
  open: boolean
  onSelectEntity: (ent: { index: number; class: string; addr: string }) => void
}

export function EntitySearchPanel({ client, open, onSelectEntity }: EntitySearchPanelProps) {
  const [field, setField] = useState('')
  const [value, setValue] = useState('')
  const [results, setResults] = useState<EntitySearchMatch[]>([])
  const [count, setCount] = useState<number | null>(null)
  const [status, setStatus] = useState<string | null>(null)

  const runSearch = async () => {
    if (!field && !value) {
      setStatus('Enter a field name or value')
      return
    }

    setStatus('Searching...')
    setResults([])
    setCount(null)

    try {
      const args: Record<string, unknown> = { max_results: 50 }
      if (field) args.field = field
      if (value) args.value = value
      const data = (await client.send('entity.search', args)) as EntitySearchResult

      if (!data.matches || data.matches.length === 0) {
        setStatus('No matches')
        return
      }

      setResults(data.matches)
      setCount(data.count)
      setStatus(null)
    } catch (e) {
      setStatus((e as Error).message || 'Search failed')
    }
  }

  if (!open) return null

  return (
    <div className="ent-search-panel open">
      <label style={{ fontSize: '.78rem', color: 'var(--t2)' }}>
        Field:{' '}
      </label>
      <input
        type="text"
        placeholder="e.g. m_iHealth"
        value={field}
        onChange={(e) => setField(e.target.value)}
      />
      <label style={{ fontSize: '.78rem', color: 'var(--t2)' }}>
        {' '}
        Value:{' '}
      </label>
      <input
        type="text"
        placeholder="e.g. 100"
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      <button className="btn btn--s" onClick={runSearch}>
        Search
      </button>
      <div className="ent-search-results">
        {status && (
          <div style={{ color: status === 'Searching...' ? 'var(--t3)' : 'var(--err)', fontSize: '.78rem' }}>
            {status}
          </div>
        )}
        {results.map((m, i) => {
          const valDisplay =
            typeof m.field_value === 'object' && m.field_value !== null
              ? JSON.stringify(m.field_value)
              : String(m.field_value)
          return (
            <div
              key={i}
              className="ent-search-result"
              title={m.addr}
              onClick={() =>
                onSelectEntity({
                  index: m.entity_index,
                  class: m.class,
                  addr: m.addr,
                })
              }
            >
              <span className="sr-class">
                [{m.entity_index}] {m.class}
              </span>{' '}
              <span className="sr-field">{m.field_name}</span>
              <span className="sr-val">{valDisplay}</span>
            </div>
          )
        })}
        {count !== null && (
          <div style={{ fontSize: '.72rem', color: 'var(--t3)', marginTop: 4 }}>
            {count} match{count !== 1 ? 'es' : ''}
          </div>
        )}
      </div>
    </div>
  )
}
