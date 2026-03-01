import { createContext, useContext, useState, useEffect, useCallback, useMemo, type ReactNode } from 'react'
import { useLive } from './live-context'
import type { EntityListItem, EntityConfig } from '../types/entity'

interface EntityContextValue {
  entityListData: EntityListItem[] | null
  entityConfig: EntityConfig | null
  selectedEntity: EntityListItem | null
  entityFilter: string
  setEntityFilter: (v: string) => void
  selectEntity: (ent: EntityListItem) => void
  refreshEntityList: () => void
  autoRefresh: boolean
  setAutoRefresh: (v: boolean) => void
}

const EntityContext = createContext<EntityContextValue>(null!)

export function useEntity() {
  return useContext(EntityContext)
}

export function EntityProvider({ children }: { children: ReactNode }) {
  const { client, connected, conLog } = useLive()
  const [entityListData, setEntityListData] = useState<EntityListItem[] | null>(null)
  const [entityConfig, setEntityConfig] = useState<EntityConfig | null>(null)
  const [selectedEntity, setSelectedEntity] = useState<EntityListItem | null>(null)
  const [entityFilter, setEntityFilter] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(false)

  const fetchEntityConfig = useCallback(async () => {
    if (!connected) return
    try {
      const config = (await client.send('entity.config', {})) as EntityConfig
      setEntityConfig(config)
    } catch (e) {
      conLog('warn', 'entity.config failed: ' + ((e as Error).message || e))
    }
  }, [client, connected, conLog])

  const refreshEntityList = useCallback(async () => {
    if (!connected) return
    if (!entityConfig) fetchEntityConfig()
    try {
      const result = (await client.send('entity.list', { max_chunks: 64 })) as {
        entities: EntityListItem[]
      }
      setEntityListData(result.entities || [])
    } catch (e) {
      conLog('error', 'entity.list failed: ' + ((e as Error).message || e))
    }
  }, [client, connected, entityConfig, fetchEntityConfig, conLog])

  // Fetch entity list on mount when connected
  useEffect(() => {
    if (connected && !entityListData) {
      refreshEntityList()
    }
  }, [connected, entityListData, refreshEntityList])

  // Auto-refresh
  useEffect(() => {
    if (!autoRefresh) return
    const timer = setInterval(refreshEntityList, 2000)
    return () => clearInterval(timer)
  }, [autoRefresh, refreshEntityList])

  // Clear data on disconnect
  useEffect(() => {
    if (!connected) {
      setEntityListData(null)
      setEntityConfig(null)
      setSelectedEntity(null)
    }
  }, [connected])

  const selectEntity = useCallback((ent: EntityListItem) => {
    setSelectedEntity(ent)
  }, [])

  const value = useMemo<EntityContextValue>(
    () => ({
      entityListData,
      entityConfig,
      selectedEntity,
      entityFilter,
      setEntityFilter,
      selectEntity,
      refreshEntityList,
      autoRefresh,
      setAutoRefresh,
    }),
    [entityListData, entityConfig, selectedEntity, entityFilter, selectEntity, refreshEntityList, autoRefresh],
  )

  return <EntityContext.Provider value={value}>{children}</EntityContext.Provider>
}
