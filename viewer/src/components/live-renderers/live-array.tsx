import { useState } from 'react'
import { LiveValueCell } from './live-value-cell'

interface LiveArrayProps {
  value: unknown
}

const LABELS = ['x', 'y', 'z', 'w']

export function LiveArray({ value }: LiveArrayProps) {
  const [expanded, setExpanded] = useState(false)
  const v = value as {
    _t?: string
    items?: unknown[]
    count?: number
    type?: string
    truncated?: boolean
  }

  const items = v.items || []
  const count = v.count ?? items.length
  const elType = v.type || ''
  const isVector = v._t === 'vector'

  // Small arrays (<=4 items) for _t='array': show inline like vector
  if (!isVector && items.length <= 4 && items.length > 0) {
    return (
      <>
        {items.map((item, i) => (
          <span key={i}>
            {i > 0 && ' '}
            <span className="live-vec-label">
              {items.length <= 4 ? LABELS[i] || String(i) : String(i)}
            </span>
            <span className="live-vec-comp">
              {typeof item === 'number'
                ? Number.isInteger(item)
                  ? String(item)
                  : item.toFixed(2)
                : String(item as string)}
            </span>
          </span>
        ))}
        <span className="badge" style={{ marginLeft: 6 }}>
          {elType}[{count}]
        </span>
      </>
    )
  }

  // Large arrays / vectors: collapsible
  const label = isVector ? '' : elType + ' '
  const headerText = `${label}[${count}${v.truncated ? '+' : ''} items]`

  return (
    <span>
      <span className="live-vec-header" title={elType ? 'Element type: ' + elType : undefined}>
        {headerText}
      </span>
      {items.length > 0 && (
        <span
          className="insp-drilldown-toggle"
          style={{ marginLeft: 4, cursor: 'pointer' }}
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? ' \u25BC' : ' \u25B6'}
        </span>
      )}
      {expanded && (
        <div className="insp-drilldown">
          {items.map((item, i) => (
            <div key={i} className="insp-drilldown-field">
              <span className="dd-name">[{i}]</span>
              <span className="dd-val">
                <LiveValueCell fieldType={elType} value={item} />
              </span>
            </div>
          ))}
          {v.truncated && (
            <div className="insp-drilldown-field" style={{ color: 'var(--t3)' }}>
              ... ({count} total, showing first {items.length})
            </div>
          )}
        </div>
      )}
    </span>
  )
}
