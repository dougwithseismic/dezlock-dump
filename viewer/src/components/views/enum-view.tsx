import { useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useSchema } from '../../context/schema-context'
import { h } from '../../lib/format'

interface EnumViewProps {
  name: string
}

export function EnumView({ name }: EnumViewProps) {
  const { enumMap } = useSchema()
  const entry = enumMap.get(name)
  const parentRef = useRef<HTMLDivElement>(null)

  if (!entry) {
    return <div className="empty">Enum not found</div>
  }

  const enm = entry.o
  const mod = entry.m
  const values = enm.values || []

  return (
    <div>
      <div className="cls-hdr">
        <h2 className="cls-name">{enm.name}</h2>
        <div className="cls-meta">
          <span className="cm-item">
            <span className="cm-label">Module: </span>
            <span>{mod}</span>
          </span>
          <span className="cm-item">
            <span className="cm-label">Size: </span>
            <span>{enm.size} byte{enm.size !== 1 ? 's' : ''}</span>
          </span>
          <span className="cm-item">
            <span className="cm-label">Values: </span>
            <span>{values.length}</span>
          </span>
        </div>
      </div>

      {values.length > 0 && (
        <>
          <div className="sec-hdr">
            <span className="sec-title">Values</span>
            <span className="sec-count">{values.length}</span>
          </div>
          {values.length > 100 ? (
            <EnumValuesVirtualized values={values} parentRef={parentRef} />
          ) : (
            <div className="tw">
              <table className="ft">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Decimal</th>
                    <th>Hex</th>
                  </tr>
                </thead>
                <tbody>
                  {values.map((v, i) => (
                    <tr key={i}>
                      <td className="f-name">{v.name}</td>
                      <td className="f-size">{String(v.value)}</td>
                      <td className="f-off">{h(v.value, 1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  )
}

function EnumValuesVirtualized({
  values,
  parentRef,
}: {
  values: { name: string; value: number }[]
  parentRef: React.RefObject<HTMLDivElement | null>
}) {
  const virtualizer = useVirtualizer({
    count: values.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 28,
    overscan: 20,
  })

  const gridTemplate = '1fr 100px 100px'

  return (
    <div className="vt-grid-wrap">
      <div className="vt-grid-header" style={{ gridTemplateColumns: gridTemplate }}>
        <div className="vt-grid-th">Name</div>
        <div className="vt-grid-th">Decimal</div>
        <div className="vt-grid-th">Hex</div>
      </div>
      <div ref={parentRef} className="vt-grid-scroll">
        <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
          {virtualizer.getVirtualItems().map((vRow) => {
            const v = values[vRow.index]
            return (
              <div
                key={vRow.index}
                className="vt-grid-row"
                style={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  width: '100%',
                  height: vRow.size,
                  transform: `translateY(${vRow.start}px)`,
                  gridTemplateColumns: gridTemplate,
                }}
              >
                <div className="vt-grid-cell f-name">{v.name}</div>
                <div className="vt-grid-cell f-size">{String(v.value)}</div>
                <div className="vt-grid-cell f-off">{h(v.value, 1)}</div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
