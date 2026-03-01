import { useState } from 'react'
import { LiveValueCell } from './live-value-cell'

interface LiveStructProps {
  value: unknown
  selectedEntityAddr?: string
  fieldOffset?: number
}

export function LiveStruct({ value, selectedEntityAddr, fieldOffset }: LiveStructProps) {
  const [expanded, setExpanded] = useState(false)

  // Rich typed object from server with _t='struct'
  if (value && typeof value === 'object' && '_t' in value) {
    const v = value as {
      _t: string
      class?: string
      module?: string
      fields?: Record<string, unknown>
    }

    return (
      <span>
        <span
          className="insp-drilldown-toggle live-struct-toggle"
          title={v.module ? v.module + '::' + v.class : v.class || ''}
          onClick={() => setExpanded(!expanded)}
          style={{ cursor: 'pointer' }}
        >
          {expanded ? '\u25BC' : '\u25B6'} {'{' + v.class + '}'}
        </span>
        {expanded && v.fields && (
          <div className="insp-drilldown">
            {Object.entries(v.fields).map(([fname, fval]) => (
              <div key={fname} className="insp-drilldown-field">
                <span className="dd-name">{fname}</span>
                <span className="dd-val">
                  <LiveValueCell fieldType="" value={fval} />
                </span>
              </div>
            ))}
          </div>
        )}
      </span>
    )
  }

  // Bare struct type — show type badge + possible drilldown
  const fieldType = typeof value === 'string' ? value : ''
  let drillAddr: string | null = null

  if (typeof value === 'string' && value.startsWith('0x')) {
    drillAddr = value
  } else if (selectedEntityAddr && fieldOffset != null) {
    try {
      const base = BigInt(selectedEntityAddr)
      const off = BigInt(fieldOffset)
      drillAddr = '0x' + (base + off).toString(16).toUpperCase()
    } catch {
      /* ignore */
    }
  }

  return (
    <>
      <span className="badge" style={{ cursor: 'default' }} title="Embedded struct">
        {fieldType}
      </span>
      {drillAddr && (
        <>
          {' '}
          <span
            className="insp-drilldown-toggle"
            title="Click to drill down"
            data-drill-addr={drillAddr}
            data-drill-type={fieldType}
          >
            {'\u25B6'} {drillAddr}
          </span>
        </>
      )}
    </>
  )
}
