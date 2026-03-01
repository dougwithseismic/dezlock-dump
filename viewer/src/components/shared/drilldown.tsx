import { useState } from 'react'
import type { LiveClient } from '../../lib/live-client'
import type { DerefResult } from '../../types/entity'

interface DrilldownProps {
  addr: string
  fieldType: string
  module: string
  client: LiveClient
}

export function Drilldown({ addr, fieldType, module, client }: DrilldownProps) {
  const [expanded, setExpanded] = useState(false)
  const [result, setResult] = useState<DerefResult | null>(null)
  const [error, setError] = useState(false)
  const [loading, setLoading] = useState(false)

  const toggle = async () => {
    if (expanded) {
      setExpanded(false)
      setResult(null)
      return
    }

    setLoading(true)
    setError(false)
    try {
      const res = (await client.send('mem.deref', {
        addr,
        type: fieldType,
        module: module || '',
        size: 64,
      })) as DerefResult
      setResult(res)
      setExpanded(true)
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }

  return (
    <span>
      <span
        className="insp-drilldown-toggle"
        onClick={toggle}
        style={{ cursor: 'pointer' }}
      >
        {expanded ? '\u25BC' : '\u25B6'} {addr}
        {loading && ' ...'}
        {error && ' (error)'}
      </span>
      {expanded && result && (
        <div className="insp-drilldown">
          {result.kind === 'string' && (
            <div className="insp-drilldown-field">
              <span className="dd-val" style={{ color: 'var(--ok)' }}>
                "{result.value || ''}"
              </span>
            </div>
          )}
          {result.kind === 'object' && result.fields && (
            <>
              <div className="insp-drilldown-field">
                <span className="dd-name" style={{ color: 'var(--acc)' }}>
                  {result.class}
                </span>{' '}
                <span style={{ color: 'var(--t3)', fontSize: '.7rem' }}>@ {result.addr}</span>
              </div>
              {Object.entries(result.fields).map(([k, v]) => (
                <div key={k} className="insp-drilldown-field">
                  <span className="dd-name">{k}</span>
                  <span className="dd-val">
                    {typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)}
                  </span>
                </div>
              ))}
            </>
          )}
          {result.kind === 'raw' && (
            <div className="insp-drilldown-field">{result.hex || 'NULL'}</div>
          )}
        </div>
      )}
    </span>
  )
}
