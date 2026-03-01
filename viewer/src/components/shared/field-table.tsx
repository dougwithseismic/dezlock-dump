import { useState, useMemo, useRef, useCallback } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useSchema } from '../../context/schema-context'
import { h, extractType, liveEditorType } from '../../lib/format'
import { ClassLink } from './class-link'
import { CopyFieldButton } from './copy-field-button'
import { InlineClassExpander } from './inline-class-expander'
import type { Field, FlatField } from '../../types/schema'

interface FieldTableProps {
  fields: (Field | FlatField)[]
  showDefinedIn?: boolean
  preferModule?: string
  showLiveValues?: boolean
}

type SortKey = 'offset' | 'name' | 'type' | 'size' | 'definedIn'

const BASE_GRID = '70px minmax(0, 1.2fr) minmax(0, 2fr) 60px'

export function FieldTable({ fields, showDefinedIn, preferModule, showLiveValues }: FieldTableProps) {
  const { resolveClassMod, enumMap, classMap } = useSchema()
  const [sortCol, setSortCol] = useState<SortKey>('offset')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set())
  const parentRef = useRef<HTMLDivElement>(null)

  const sorted = useMemo(() => {
    return [...fields].sort((a, b) => {
      const va = a[sortCol] as unknown
      const vb = b[sortCol] as unknown
      const la = typeof va === 'string' ? va.toLowerCase() : va
      const lb = typeof vb === 'string' ? vb.toLowerCase() : vb
      if ((la as string | number) < (lb as string | number)) return sortDir === 'asc' ? -1 : 1
      if ((la as string | number) > (lb as string | number)) return sortDir === 'asc' ? 1 : -1
      return 0
    })
  }, [fields, sortCol, sortDir])

  const toggleExpand = useCallback((index: number) => {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(index)) next.delete(index)
      else next.add(index)
      return next
    })
  }, [])

  const virtualizer = useVirtualizer({
    count: sorted.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) => expandedRows.has(index) ? 250 : 28,
    overscan: 30,
    measureElement: (el) => el.getBoundingClientRect().height,
  })

  const handleSort = (key: SortKey) => {
    if (sortCol === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSortCol(key)
      setSortDir('asc')
    }
  }

  const thCls = (key: SortKey) =>
    'vt-grid-th' + (sortCol === key ? (sortDir === 'asc' ? ' s-asc' : ' s-desc') : '')

  const cols: { key: SortKey; label: string }[] = [
    { key: 'offset', label: 'Offset' },
    { key: 'name', label: 'Name' },
    { key: 'type', label: 'Type' },
    { key: 'size', label: 'Size' },
  ]
  if (showDefinedIn) cols.push({ key: 'definedIn', label: 'Defined In' })

  const gridTemplate = BASE_GRID +
    (showDefinedIn ? ' minmax(0, 0.8fr)' : '') +
    ' minmax(0, 1fr)' +
    (showLiveValues ? ' minmax(0, 0.8fr)' : '')

  return (
    <div className="vt-grid-wrap">
      {/* Sticky header */}
      <div className="vt-grid-header" style={{ gridTemplateColumns: gridTemplate }}>
        {cols.map((c) => (
          <div key={c.key} className={thCls(c.key)} onClick={() => handleSort(c.key)}>
            {c.label}
          </div>
        ))}
        <div className="vt-grid-th">Metadata</div>
        {showLiveValues && <div className="vt-grid-th">LIVE</div>}
      </div>

      {/* Virtualized body */}
      <div ref={parentRef} className="vt-grid-scroll">
        <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
          {virtualizer.getVirtualItems().map((vRow) => {
            const f = sorted[vRow.index]
            const typeName = extractType(f.type)
            const typeMod = typeName ? resolveClassMod(typeName, preferModule) : null
            const edType = liveEditorType(f.type, enumMap as Map<string, unknown>, classMap as Map<string, unknown>)
            const canExpand = !!typeName && !!typeMod
            const isExpanded = expandedRows.has(vRow.index)
            const copyLine = `[${preferModule || ''}]+${h(f.offset)} ${f.name}`

            return (
              <div
                key={vRow.index}
                ref={virtualizer.measureElement}
                data-index={vRow.index}
                style={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  width: '100%',
                  transform: `translateY(${vRow.start}px)`,
                }}
              >
                <div
                  className="vt-grid-row"
                  style={{ gridTemplateColumns: gridTemplate }}
                >
                  <div className="vt-grid-cell f-off">{h(f.offset)}</div>
                  <div className="vt-grid-cell f-name">
                    {f.name}
                    <CopyFieldButton text={`${copyLine} // ${f.type || ''}`} />
                  </div>
                  <div className="vt-grid-cell f-type">
                    {typeName && typeMod ? (
                      <>
                        <ClassLink
                          name={typeName}
                          module={typeMod}
                          preferModule={preferModule}
                          showCrossModuleBadge
                          onExpand={canExpand ? () => toggleExpand(vRow.index) : undefined}
                          isExpanded={isExpanded}
                        />
                        {(() => {
                          const rest = (f.type || '').replace(typeName, '').trim()
                          return rest ? ' ' + rest : ''
                        })()}
                      </>
                    ) : (
                      f.type || '\u2014'
                    )}
                  </div>
                  <div className="vt-grid-cell f-size">{f.size != null ? String(f.size) : '\u2014'}</div>
                  {showDefinedIn && (
                    <div className="vt-grid-cell f-def">
                      {(f as FlatField).definedIn ? (
                        (() => {
                          const defMod = resolveClassMod((f as FlatField).definedIn, preferModule)
                          return defMod ? (
                            <ClassLink name={(f as FlatField).definedIn} module={defMod} />
                          ) : (
                            (f as FlatField).definedIn
                          )
                        })()
                      ) : null}
                    </div>
                  )}
                  <div className="vt-grid-cell">
                    {f.metadata?.map((m, mi) => (
                      <span key={mi} className={'badge' + (m.includes('Network') ? ' badge-net' : '')}>
                        {m}{' '}
                      </span>
                    ))}
                  </div>
                  {showLiveValues && (
                    <div
                      className="vt-grid-cell live-val"
                      data-live-field={f.name}
                      data-live-type={f.type}
                      data-editor-type={edType}
                      data-field-offset={f.offset}
                    >
                      {'\u2014'}
                    </div>
                  )}
                </div>
                {isExpanded && typeName && typeMod && (
                  <div className="inline-expand-row">
                    <InlineClassExpander
                      className={typeName}
                      module={typeMod}
                      preferModule={preferModule}
                      depth={1}
                      copyPrefix={copyLine}
                    />
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
