import { useMemo, useRef, useCallback, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useLive } from '../../context/live-context'
import { useEntity } from '../../context/entity-context'
import { EntityRow } from './entity-row'
import { EntitySearchPanel } from './entity-search-panel'
import type { EntityListItem } from '../../types/entity'

interface EntitySidebarListProps {
  height: number
}

export function EntitySidebarList({ height }: EntitySidebarListProps) {
  const { client } = useLive()
  const {
    entityListData,
    entityConfig,
    selectedEntity,
    entityFilter,
    setEntityFilter,
    selectEntity,
    refreshEntityList,
    autoRefresh,
    setAutoRefresh,
  } = useEntity()

  const [searchOpen, setSearchOpen] = useState(false)
  const parentRef = useRef<HTMLDivElement>(null)

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

  const handleRowClick = useCallback(
    (e: React.MouseEvent) => {
      const row = (e.target as HTMLElement).closest('.ent-row') as HTMLElement | null
      if (!row) return
      const addr = row.dataset.addr
      if (addr) {
        const ent = filtered.find((en) => en.addr === addr)
        if (ent) selectEntity(ent)
      }
    },
    [filtered, selectEntity],
  )

  const handleSearchSelect = useCallback(
    (ent: { index: number; class: string; addr: string }) => {
      selectEntity(ent as EntityListItem)
    },
    [selectEntity],
  )

  const configTip = entityConfig
    ? `stride: 0x${entityConfig.identity_stride.toString(16).toUpperCase()}\nchunk_offset: 0x${entityConfig.chunk_offset.toString(16).toUpperCase()}\nchunks: ${entityConfig.max_chunks} \u00D7 ${entityConfig.chunk_size}\ndesigner_name: +0x${entityConfig.designer_name_offset.toString(16).toUpperCase()}\nGES: ${entityConfig.ges_addr}`
    : ''

  const toolbarHeight = 38
  const searchPanelHeight = searchOpen ? 120 : 0
  const listH = Math.max(100, height - toolbarHeight - searchPanelHeight)

  return (
    <div className="flex-1 flex flex-col" style={{ minHeight: 0 }}>
      <div className="ent-list-toolbar">
        <input
          type="text"
          placeholder="Filter class..."
          value={entityFilter}
          onInput={(e) => setEntityFilter((e.target as HTMLInputElement).value)}
          style={{ flex: 1, minWidth: 0 }}
        />
        <button className="btn btn--s" title="Refresh entity list" onClick={refreshEntityList}>
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
          {entityListData ? `${filtered.length}/${entityListData.length}` : '...'}
        </span>
        <span
          className={'ent-config-badge' + (entityConfig?.probed ? ' probed' : '')}
          title={configTip}
        >
          {entityConfig ? (entityConfig.probed ? '\u2713 probed' : 'fallback') : '...'}
        </span>
        <button
          className="btn btn--s"
          title="Search entities by field/value"
          onClick={() => setSearchOpen(!searchOpen)}
        >
          {'\uD83D\uDD0D'}
        </button>
      </div>

      <EntitySearchPanel client={client} open={searchOpen} onSelectEntity={handleSearchSelect} />

      <div
        ref={parentRef}
        style={{ height: listH, overflow: 'auto' }}
        onClick={handleRowClick}
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
