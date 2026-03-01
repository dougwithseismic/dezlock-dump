import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useSchema } from '../../context/schema-context'
import { useLive } from '../../context/live-context'
import { flatFields } from '../../lib/flat-fields'
import { liveEditorType, extractType } from '../../lib/format'
import type { EntityListItem } from '../../types/entity'
import type { FlatField } from '../../types/schema'
import type { DiffChanges } from '../../types/live'
import { EntityInspectorToolbar } from './entity-inspector-toolbar'
import { EntityInspectorField } from './entity-inspector-field'
import { ColumnResizeHandle } from './column-resize-handle'
import { InlineClassExpander } from '../shared/inline-class-expander'

interface EntityInspectorPaneProps {
  entity: EntityListItem | null
  entityListData: EntityListItem[] | null
  onFollowEntity?: (ent: EntityListItem) => void
}

type VirtualItem =
  | { type: 'section-header'; groupName: string; fieldCount: number }
  | { type: 'field'; field: FlatField; groupName: string }
  | { type: 'inline-expand'; typeName: string; typeMod: string; fieldKey: string; parentFieldName: string }

function extractNestedLiveValues(
  liveValues: Record<string, unknown>,
  fieldName: string,
): Record<string, unknown> | undefined {
  const val = liveValues[fieldName]
  if (val && typeof val === 'object' && '_t' in (val as Record<string, unknown>)) {
    const sv = val as { _t: string; fields?: Record<string, unknown> }
    if (sv._t === 'struct' && sv.fields) return sv.fields
  }
  return undefined
}

export function EntityInspectorPane({
  entity,
  entityListData,
  onFollowEntity,
}: EntityInspectorPaneProps) {
  const { client, connected } = useLive()
  const { classMap, enumMap, resolveClassMod } = useSchema()
  const [fieldFilter, setFieldFilter] = useState('')
  const [expandedFields, setExpandedFields] = useState<Set<string>>(new Set())
  const [showChanged, setShowChanged] = useState(false)
  const [snapshotActive, setSnapshotActive] = useState(false)
  const [liveValues, setLiveValues] = useState<Record<string, unknown>>({})
  const [changedFields, setChangedFields] = useState<Set<string>>(new Set())
  const [diffFlashFields, setDiffFlashFields] = useState<Set<string>>(new Set())
  const [flashTick, setFlashTick] = useState(0)
  const [collapsedSections, setCollapsedSections] = useState<Map<string, boolean>>(new Map())

  const snapshotRef = useRef<Record<string, string>>({})
  const frozenRef = useRef<Record<string, string> | null>(null)
  const subIdRef = useRef<number | null>(null)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const treeRef = useRef<HTMLDivElement>(null)
  const scrollRef = useRef<HTMLDivElement>(null)

  // Resolve entity class
  const resolveEntityClass = useCallback(
    (className: string) => {
      const ce = classMap.get(className)
      if (ce) return ce
      const alt = className.replace(/^C_/, 'C')
      return classMap.get(alt) || null
    },
    [classMap],
  )

  const ce = entity ? resolveEntityClass(entity.class) : null
  const className = ce ? ce.o.name : entity?.class || ''
  const mod = ce ? ce.m : ''
  const flat = ce ? flatFields(className, classMap) : []

  // Group fields by definedIn
  const groups = useMemo(() => {
    const result: { name: string; fields: FlatField[] }[] = []
    const gm = new Map<string, FlatField[]>()
    for (const f of flat) {
      const key = f.definedIn || className
      if (!gm.has(key)) {
        gm.set(key, [])
        result.push({ name: key, fields: gm.get(key)! })
      }
      gm.get(key)!.push(f)
    }
    return result
  }, [flat, className])

  // Apply filters
  const isFieldVisible = useCallback((f: FlatField) => {
    const lf = fieldFilter.toLowerCase()
    const matchFilter =
      !lf || f.name.toLowerCase().includes(lf) || (f.type || '').toLowerCase().includes(lf)
    const matchChanged = !showChanged || changedFields.has(f.name)
    return matchFilter && matchChanged
  }, [fieldFilter, showChanged, changedFields])

  // Build flat virtual item list
  const virtualItems = useMemo<VirtualItem[]>(() => {
    const items: VirtualItem[] = []
    for (const group of groups) {
      const visibleFields = group.fields.filter(isFieldVisible)
      if (visibleFields.length === 0) continue
      items.push({ type: 'section-header', groupName: group.name, fieldCount: group.fields.length })
      if (!collapsedSections.get(group.name)) {
        for (const field of visibleFields) {
          const fieldKey = field.name + ':' + field.offset
          items.push({ type: 'field', field, groupName: group.name })
          if (expandedFields.has(fieldKey)) {
            const typeName = extractType(field.type)
            const typeMod = typeName ? resolveClassMod(typeName, mod) : null
            if (typeName && typeMod) {
              items.push({ type: 'inline-expand', typeName, typeMod, fieldKey, parentFieldName: field.name })
            }
          }
        }
      }
    }
    return items
  }, [groups, isFieldVisible, collapsedSections, expandedFields, resolveClassMod, mod])

  const virtualizer = useVirtualizer({
    count: virtualItems.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: (i) => {
      const item = virtualItems[i]
      if (item.type === 'section-header') return 30
      if (item.type === 'inline-expand') return 250
      return 28
    },
    overscan: 20,
    measureElement: (el) => el.getBoundingClientRect().height,
  })

  const toggleSection = useCallback((name: string) => {
    setCollapsedSections((prev) => {
      const next = new Map(prev)
      next.set(name, !prev.get(name))
      return next
    })
  }, [])

  const toggleFieldExpand = useCallback((fieldKey: string) => {
    setExpandedFields((prev) => {
      const next = new Set(prev)
      if (next.has(fieldKey)) next.delete(fieldKey)
      else next.add(fieldKey)
      return next
    })
  }, [])

  // Stop inspector polling/subscription
  const stopInspector = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
    if (subIdRef.current !== null && client) {
      client.unsubscribe(subIdRef.current).catch(() => {})
      subIdRef.current = null
    }
  }, [client])

  const flashTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Update fields from server data
  const updateFields = useCallback(
    (data: Record<string, unknown>) => {
      const ref = frozenRef.current || snapshotRef.current
      const flashSet = new Set<string>()

      for (const fname of Object.keys(data)) {
        const newStr = JSON.stringify(data[fname])
        const oldStr = ref[fname]
        if (oldStr !== undefined && oldStr !== newStr) {
          flashSet.add(fname)
        }
        snapshotRef.current[fname] = newStr
      }

      setLiveValues((prev) => ({ ...prev, ...data }))
      if (flashSet.size > 0) {
        setChangedFields((prev) => {
          const next = new Set(prev)
          for (const f of flashSet) next.add(f)
          return next
        })
        setDiffFlashFields(flashSet)
        setFlashTick((t) => t + 1)
        if (flashTimerRef.current) clearTimeout(flashTimerRef.current)
        flashTimerRef.current = setTimeout(() => setDiffFlashFields(new Set()), 400)
      }
    },
    [],
  )

  // Refresh entity inspector via full read
  const refreshInspector = useCallback(
    async (addr: string, m: string, cn: string) => {
      if (!connected) {
        stopInspector()
        return
      }
      try {
        const data = (await client.send('mem.read_object', {
          addr,
          module: m,
          class: cn,
        })) as Record<string, unknown>
        updateFields(data)
      } catch {
        /* silently skip */
      }
    },
    [client, connected, stopInspector, updateFields],
  )

  // Start live reading when entity changes
  useEffect(() => {
    if (!entity || !ce || !connected) return

    const addr = entity.addr
    const m = ce.m
    const cn = ce.o.name

    // Reset state
    snapshotRef.current = {}
    frozenRef.current = null
    setLiveValues({})
    setChangedFields(new Set())
    setSnapshotActive(false)
    setExpandedFields(new Set())

    let cancelled = false

    const start = async () => {
      // Try subscription first
      try {
        const result = await client.subscribe(addr, m, cn, 100, (changes: DiffChanges) => {
          if (cancelled) return
          const parsed: Record<string, unknown> = {}
          for (const fname of Object.keys(changes)) {
            const change = changes[fname]
            if (change && typeof change === 'object' && 'new' in (change as Record<string, unknown>)) {
              parsed[fname] = (change as Record<string, unknown>)['new']
            } else {
              parsed[fname] = change
            }
          }
          updateFields(parsed)
        })
        if (result?.sub_id !== undefined) {
          subIdRef.current = result.sub_id
          refreshInspector(addr, m, cn)
          return
        }
      } catch {
        /* subscription not supported, fall back to polling */
      }

      // Polling fallback
      refreshInspector(addr, m, cn)
      timerRef.current = setInterval(() => {
        if (!cancelled) refreshInspector(addr, m, cn)
      }, 500)
    }

    start()

    return () => {
      cancelled = true
      stopInspector()
      if (flashTimerRef.current) clearTimeout(flashTimerRef.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entity?.addr, ce?.o.name, connected])

  // Handle click delegation for drilldowns and handle follows
  const handleTreeClick = useCallback(
    (e: React.MouseEvent) => {
      const target = e.target as HTMLElement

      // Handle entity follow (click on .live-handle)
      const handleEl = target.closest('.live-handle') as HTMLElement
      if (handleEl && entityListData && onFollowEntity) {
        const match = handleEl.textContent?.match(/ent:(\d+)/)
        if (match) {
          const idx = parseInt(match[1], 10)
          const targetEnt = entityListData.find((ent) => ent.index === idx)
          if (targetEnt) {
            onFollowEntity(targetEnt)
            return
          }
        }
      }
    },
    [entityListData, onFollowEntity],
  )

  // Snapshot handlers
  const handleSnapshot = () => {
    frozenRef.current = { ...snapshotRef.current }
    setSnapshotActive(true)
  }
  const handleClearSnapshot = () => {
    frozenRef.current = null
    setSnapshotActive(false)
  }

  // Restore persisted column width (read once)
  const savedColWRef = useRef(typeof localStorage !== 'undefined' ? localStorage.getItem('ent-insp-val-col') : null)
  const savedColW = savedColWRef.current

  if (!entity) {
    return (
      <div className="ent-inspector-pane">
        <div className="empty">
          <p>Select an entity to inspect</p>
        </div>
      </div>
    )
  }

  return (
    <div className="ent-inspector-pane" onClick={handleTreeClick}>
      <div className="insp-hdr">
        <div className="insp-hdr-name">{className}</div>
        <div className="insp-hdr-meta">
          <span>Index: {entity.index}</span>
          <span>{entity.addr}</span>
          {mod && <span>{mod}</span>}
        </div>
      </div>

      {!ce && <div className="empty">Class not in schema</div>}

      {ce && flat.length === 0 && <div className="empty">No fields</div>}

      {ce && flat.length > 0 && (
        <>
          <EntityInspectorToolbar
            fieldFilter={fieldFilter}
            onFieldFilterChange={setFieldFilter}
            showChanged={showChanged}
            onShowChangedChange={setShowChanged}
            onSnapshot={handleSnapshot}
            onClearSnapshot={handleClearSnapshot}
            snapshotActive={snapshotActive}
          />

          <div
            ref={treeRef}
            className="insp-virtual-wrap"
            style={savedColW ? { '--val-col-w': savedColW + 'px' } as React.CSSProperties : undefined}
          >
            <div
              className="insp-field insp-col-resize-wrap"
              style={{
                borderBottom: '2px solid var(--brd)',
                fontSize: '.72rem',
                color: 'var(--t3)',
                fontWeight: 600,
                userSelect: 'none',
              }}
            >
              <div className="insp-field-name">Field</div>
              <div className="insp-field-val" style={{ position: 'relative' }}>
                Value
                <ColumnResizeHandle containerRef={treeRef} />
              </div>
            </div>

            <div ref={scrollRef} className="insp-virtual-scroll">
              <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
                {virtualizer.getVirtualItems().map((vRow) => {
                  const item = virtualItems[vRow.index]
                  const style: React.CSSProperties = {
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    transform: `translateY(${vRow.start}px)`,
                  }

                  if (item.type === 'section-header') {
                    const isCollapsed = collapsedSections.get(item.groupName) || false
                    return (
                      <div
                        key={'sh-' + item.groupName}
                        ref={virtualizer.measureElement}
                        data-index={vRow.index}
                        style={style}
                      >
                        <div
                          className="insp-section-hdr"
                          onClick={() => toggleSection(item.groupName)}
                        >
                          <span className={'insp-section-arrow' + (isCollapsed ? ' collapsed' : '')}>
                            {'\u25BE'}
                          </span>
                          {item.groupName}
                          <span
                            style={{
                              fontWeight: 400,
                              color: 'var(--t3)',
                              fontSize: '.75rem',
                              marginLeft: 4,
                            }}
                          >
                            {' '}
                            ({item.fieldCount})
                          </span>
                        </div>
                      </div>
                    )
                  }

                  if (item.type === 'inline-expand') {
                    const nestedLive = extractNestedLiveValues(liveValues, item.parentFieldName) ?? {}
                    return (
                      <div
                        key={'ie-' + item.fieldKey}
                        ref={virtualizer.measureElement}
                        data-index={vRow.index}
                        style={style}
                      >
                        <div className="insp-inline-expand-wrap">
                          <InlineClassExpander
                            className={item.typeName}
                            module={item.typeMod}
                            preferModule={mod}
                            depth={1}
                            copyPrefix={`[${mod}] ${item.typeName}`}
                            liveValues={nestedLive}
                            enumMap={enumMap as Map<string, { o: { items?: { name: string; value: number }[] } }>}
                            classMap={classMap as Map<string, unknown>}
                            selectedEntityAddr={entity.addr}
                          />
                        </div>
                      </div>
                    )
                  }

                  const f = item.field
                  const fieldKey = f.name + ':' + f.offset
                  const typeName = extractType(f.type)
                  const typeMod = typeName ? resolveClassMod(typeName, mod) : null
                  const canExpand = !!typeName && !!typeMod
                  const isFieldExpanded = expandedFields.has(fieldKey)
                  return (
                    <div
                      key={'f-' + f.name + f.offset}
                      ref={virtualizer.measureElement}
                      data-index={vRow.index}
                      style={style}
                    >
                      <EntityInspectorField
                        name={f.name}
                        type={f.type}
                        offset={f.offset}
                        liveValue={liveValues[f.name] ?? null}
                        editorType={liveEditorType(f.type, enumMap as Map<string, { o: { items?: { name: string; value: number }[] } }>, classMap as Map<string, unknown>)}
                        module={mod}
                        diffFlash={diffFlashFields.has(f.name)}
                        flashTick={flashTick}
                        diffTitle={
                          changedFields.has(f.name) && snapshotRef.current[f.name]
                            ? 'Was: ' + snapshotRef.current[f.name]
                            : undefined
                        }
                        enumMap={enumMap as Map<string, { o: { items?: { name: string; value: number }[] } }>}
                        classMap={classMap as Map<string, unknown>}
                        selectedEntityAddr={entity.addr}
                        onExpand={canExpand ? () => toggleFieldExpand(fieldKey) : undefined}
                        isExpanded={isFieldExpanded}
                      />
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
