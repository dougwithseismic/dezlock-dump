import { useState, useRef, useCallback, useEffect, useMemo } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useLive } from '../../context/live-context'
import type { EntityListItem, EntityConfig } from '../../types/entity'
import { EntityRow } from './entity-row'
import { EntitySearchPanel } from './entity-search-panel'

interface EntityListPaneProps {
  entityListData: EntityListItem[] | null
  entityConfig: EntityConfig | null
  selectedEntity: EntityListItem | null
  entityFilter: string
  onFilterChange: (v: string) => void
  onSelectEntity: (ent: EntityListItem) => void
  onRefresh: () => void
}

export function EntityListPane({
  entityListData,
  entityConfig,
  selectedEntity,
  entityFilter,
  onFilterChange,
  onSelectEntity,
  onRefresh,
}: EntityListPaneProps) {
  const { client } = useLive()
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [searchOpen, setSearchOpen] = useState(false)
  const autoTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const parentRef = useRef<HTMLDivElement>(null)

  // Auto-refresh
  useEffect(() => {
    if (autoRefresh) {
      autoTimerRef.current = setInterval(onRefresh, 2000)
    } else if (autoTimerRef.current) {
      clearInterval(autoTimerRef.current)
      autoTimerRef.current = null
    }
    return () => {
      if (autoTimerRef.current) clearInterval(autoTimerRef.current)
    }
  }, [autoRefresh, onRefresh])

  // Filter entities
  const filtered = useMemo(() => {
    if (!entityListData) return []
    if (!entityFilter) return entityListData
    const lf = entityFilter.toLowerCase()
    return entityListData.filter(
      (e) =>
        e.class.toLowerCase().includes(lf) ||
        (e.designer_name && e.designer_name.toLowerCase().includes(lf)),
    )
  }, [entityListData, entityFilter])

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 28,
    overscan: 20,
  })

  // Config tooltip
  const configTip = entityConfig
    ? `stride: 0x${entityConfig.identity_stride.toString(16).toUpperCase()}\nchunk_offset: 0x${entityConfig.chunk_offset.toString(16).toUpperCase()}\nchunks: ${entityConfig.max_chunks} \u00D7 ${entityConfig.chunk_size}\ndesigner_name: +0x${entityConfig.designer_name_offset.toString(16).toUpperCase()}\nGES: ${entityConfig.ges_addr}`
    : ''

  const handleSearchSelect = useCallback(
    (ent: { index: number; class: string; addr: string }) => {
      onSelectEntity(ent as EntityListItem)
    },
    [onSelectEntity],
  )

  return (
    <div className="ent-list-pane">
      <div className="ent-list-toolbar">
        <input
          type="text"
          placeholder="Filter class..."
          value={entityFilter}
          onInput={(e) => onFilterChange((e.target as HTMLInputElement).value)}
        />
        <button className="btn btn--s" title="Refresh entity list" onClick={onRefresh}>
          {'\u21BB'}
        </button>
        <label className="ent-auto">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
          />
          {' Auto'}
        </label>
        <span className="ent-count">
          {entityListData
            ? `${filtered.length}/${entityListData.length}`
            : '...'}
        </span>
        <span
          className={
            'ent-config-badge' + (entityConfig?.probed ? ' probed' : '')
          }
          title={configTip}
        >
          {entityConfig
            ? entityConfig.probed
              ? '\u2713 probed'
              : 'fallback'
            : '...'}
        </span>
        <button
          className="btn btn--s"
          title="Search entities by field/value"
          onClick={() => setSearchOpen(!searchOpen)}
        >
          {'\uD83D\uDD0D'}
        </button>
      </div>

      <EntitySearchPanel
        client={client}
        open={searchOpen}
        onSelectEntity={handleSearchSelect}
      />

      <div
        ref={parentRef}
        className="ent-list-body"
        onClick={(e) => {
          const row = (e.target as HTMLElement).closest('.ent-row') as HTMLElement | null
          if (!row) return
          const addr = row.dataset.addr
          if (addr) {
            const ent = filtered.find((e) => e.addr === addr)
            if (ent) onSelectEntity(ent)
          }
        }}
      >
        <div
          style={{
            height: virtualizer.getTotalSize(),
            width: '100%',
            position: 'relative',
          }}
        >
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const ent = filtered[virtualRow.index]
            return (
              <EntityRow
                key={ent.addr}
                entity={ent}
                selected={selectedEntity?.addr === ent.addr}
                style={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  width: '100%',
                  height: virtualRow.size,
                  transform: `translateY(${virtualRow.start}px)`,
                }}
              />
            )
          })}
        </div>
      </div>
    </div>
  )
}
