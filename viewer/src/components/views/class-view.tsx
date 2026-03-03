import { useState, useRef, useEffect, useCallback, useMemo } from 'react'
import { useSchema } from '../../context/schema-context'
import { useLive } from '../../context/live-context'
import { h } from '../../lib/format'
import { flatFields } from '../../lib/flat-fields'
import { ClassLink } from '../shared/class-link'
import { Badge } from '../shared/badge'
import { FieldTable } from '../shared/field-table'
import { SectionHeader } from '../shared/section-header'
import type { FlatField } from '../../types/schema'

interface ClassViewProps {
  name: string
  module: string
}

export function ClassView({ name, module }: ClassViewProps) {
  const { classMap, resolveClassMod } = useSchema()
  const { client, connected, conLog } = useLive()
  const [showFlat, setShowFlat] = useState(false)
  const [liveAddr, setLiveAddr] = useState('')
  const [watching, setWatching] = useState(false)
  const addrInputRef = useRef<HTMLInputElement>(null)
  const subIdRef = useRef<number | null>(null)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const entry = classMap.get(name)

  const stopLive = useCallback(() => {
    if (subIdRef.current !== null) {
      client.unsubscribe(subIdRef.current).catch(() => {})
      subIdRef.current = null
    }
    if (timerRef.current !== null) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
    setWatching(false)
  }, [client])

  // Cleanup on unmount or name change
  useEffect(() => {
    return () => { stopLive() }
  }, [name, module, stopLive])

  if (!entry) {
    return <div className="empty">Class "{name}" not found</div>
  }

  const mod = module || entry.m
  const cls = entry.perMod?.[mod] ?? entry.o
  const own = cls.fields || []
  const flat = flatFields(cls.name, classMap)
  const hasFlat = flat.length > own.length

  const ownAsFlat = useMemo<FlatField[]>(() => own.map((f) => ({ ...f, definedIn: cls.name })), [own, cls.name])
  const displayFields = showFlat ? flat : ownAsFlat

  const startLive = async () => {
    const addr = addrInputRef.current?.value.trim() || ''
    if (!addr) return
    setLiveAddr(addr)
    setWatching(true)
    stopLive()

    const refreshFields = async () => {
      if (!client.connected) { stopLive(); return }
      try {
        const data = (await client.send('mem.read_object', {
          addr, module: mod, class: cls.name,
        })) as Record<string, unknown>
        const cells = document.querySelectorAll<HTMLElement>('td[data-live-field]')
        cells.forEach((td) => {
          const fname = td.dataset.liveField!
          if (data[fname] !== undefined) {
            td.textContent = typeof data[fname] === 'object'
              ? JSON.stringify(data[fname])
              : String(data[fname])
          }
        })
      } catch { /* silently skip */ }
    }

    try {
      const result = await client.subscribe(addr, mod, cls.name, 100, (changes) => {
        const cells = document.querySelectorAll<HTMLElement>('td[data-live-field]')
        cells.forEach((td) => {
          const fname = td.dataset.liveField!
          if (changes[fname] !== undefined) {
            const change = changes[fname] as { new?: unknown; old?: unknown }
            const newVal = change.new !== undefined ? change.new : change
            td.textContent = typeof newVal === 'object' ? JSON.stringify(newVal) : String(newVal)
            td.classList.remove('live-diff-flash')
            void td.offsetWidth
            td.classList.add('live-diff-flash')
          }
        })
      })
      if (result?.sub_id !== undefined) {
        subIdRef.current = result.sub_id
        conLog('info', 'Subscribed to ' + cls.name + ' (sub_id: ' + result.sub_id + ')')
        refreshFields()
        return
      }
    } catch { /* subscription not supported, fall back to polling */ }

    refreshFields()
    timerRef.current = setInterval(refreshFields, 500)
  }

  const handleWatch = () => {
    if (watching) {
      stopLive()
      setLiveAddr('')
    } else {
      startLive()
    }
  }

  return (
    <div>
      <div className="cls-hdr">
        <h2 className="cls-name">{cls.name}</h2>
        <div className="cls-meta">
          <span className="cm-item">
            <span className="cm-label">Module: </span><span>{mod}</span>
          </span>
          <span className="cm-item">
            <span className="cm-label">Size: </span>
            <span>{cls.size} bytes ({h(cls.size)})</span>
          </span>
          {cls.fields && (
            <span className="cm-item">
              <span className="cm-label">Fields: </span><span>{cls.fields.length}</span>
            </span>
          )}
        </div>

        {/* Inheritance */}
        {cls.inheritance && cls.inheritance.length > 1 ? (
          <div className="cls-chain">
            <span className="cm-label">Inherits: </span>
            {cls.inheritance.map((cn, i) => {
              const cnMod = resolveClassMod(cn, mod)
              return (
                <span key={i}>
                  {i > 0 && <span className="cls-sep"> {'\u203A'} </span>}
                  {cnMod && cn !== cls.name ? (
                    <ClassLink name={cn} module={cnMod} />
                  ) : (
                    <span className={i === 0 ? 'f-type' : ''}>{cn}</span>
                  )}
                </span>
              )
            })}
          </div>
        ) : cls.parent ? (
          <div className="cls-chain">
            <span className="cm-label">Parent: </span>
            {(() => {
              const pMod = resolveClassMod(cls.parent, mod)
              return pMod ? <ClassLink name={cls.parent} module={pMod} /> : <span>{cls.parent}</span>
            })()}
          </div>
        ) : null}

        {/* Badges */}
        {cls.metadata && cls.metadata.length > 0 && (
          <div className="badges">
            {cls.metadata.map((m, i) => (
              <Badge key={i} text={m} variant={m.includes('Network') ? 'net' : 'default'} />
            ))}
          </div>
        )}
      </div>

      {/* Live Read Section */}
      {connected && (
        <div className="live-read-section">
          <label style={{ fontWeight: 600 }}>Address</label>{' '}
          <input
            ref={addrInputRef}
            type="text"
            placeholder="0x7FF012345678"
            defaultValue={liveAddr}
            id="live-read-addr"
          />{' '}
          <button
            className="btn btn--s"
            onClick={handleWatch}
            style={watching ? { background: 'var(--brd)' } : undefined}
          >
            {watching ? 'Stop' : 'Watch'}
          </button>
        </div>
      )}

      {/* Components */}
      {cls.components && cls.components.length > 0 && (
        <div>
          <SectionHeader title="Components" count={cls.components.length} />
          <div className="tw">
            <table className="ft">
              <thead>
                <tr>
                  <th>Offset</th>
                  <th>Name</th>
                </tr>
              </thead>
              <tbody>
                {cls.components.map((comp, i) => {
                  const compMod = resolveClassMod(comp.name, mod)
                  return (
                    <tr key={i}>
                      <td className="f-off">{h(comp.offset)}</td>
                      <td className="f-name">
                        {compMod ? <ClassLink name={comp.name} module={compMod} /> : comp.name}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Fields */}
      {(own.length > 0 || flat.length > 0) && (
        <div>
          <SectionHeader
            title="Fields"
            count={displayFields.length + ' fields'}
            toggleLabel={hasFlat ? (showFlat ? 'Show own only' : 'Show flattened') : undefined}
            onToggle={hasFlat ? () => setShowFlat((p) => !p) : undefined}
          >
            <button
              className="btn btn--s"
              style={{ marginLeft: 'auto' }}
              onClick={() => {
                const pointerFields = displayFields
                  .filter((f) => f.type && f.type.includes('*'))
                  .map((f) => `[${mod}]+${h(f.offset)} ${f.name} // ${f.type}`)
                  .join('\n')
                if (pointerFields) {
                  navigator.clipboard.writeText(pointerFields)
                } else {
                  navigator.clipboard.writeText('// No pointer fields found')
                }
              }}
              title="Copy all pointer fields to clipboard"
            >
              Copy Pointer List
            </button>
          </SectionHeader>
          <FieldTable
            fields={displayFields}
            showDefinedIn={showFlat}
            preferModule={mod}
            showLiveValues={connected}
          />
        </div>
      )}

      {/* Static Fields */}
      {cls.static_fields && cls.static_fields.length > 0 && (
        <div>
          <SectionHeader title="Static Fields" count={cls.static_fields.length} />
          <FieldTable
            fields={cls.static_fields.map((f) => ({ ...f, definedIn: cls.name }))}
            showDefinedIn={false}
            preferModule={mod}
            showLiveValues={connected}
          />
        </div>
      )}
    </div>
  )
}
