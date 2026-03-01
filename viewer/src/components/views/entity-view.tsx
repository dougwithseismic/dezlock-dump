import { useState, useEffect, useCallback } from 'react'
import { useLive } from '../../context/live-context'
import type { EntityListItem, EntityConfig } from '../../types/entity'
import { EntityListPane } from '../entity/entity-list-pane'
import { EntityInspectorPane } from '../entity/entity-inspector-pane'

export function EntityView() {
  const { client, connected, conLog } = useLive()
  const [entityListData, setEntityListData] = useState<EntityListItem[] | null>(null)
  const [entityConfig, setEntityConfig] = useState<EntityConfig | null>(null)
  const [selectedEntity, setSelectedEntity] = useState<EntityListItem | null>(null)
  const [entityFilter, setEntityFilter] = useState('')

  const fetchEntityConfig = useCallback(async () => {
    if (!connected) return
    try {
      const config = (await client.send('entity.config', {})) as EntityConfig
      setEntityConfig(config)
    } catch (e) {
      conLog('warn', 'entity.config failed: ' + ((e as Error).message || e))
    }
  }, [client, connected, conLog])

  const fetchEntityList = useCallback(async () => {
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
      fetchEntityList()
    }
  }, [connected, entityListData, fetchEntityList])

  const handleSelectEntity = useCallback((ent: EntityListItem) => {
    setSelectedEntity(ent)
  }, [])

  if (!connected) {
    return (
      <div className="empty">
        <p>Connect live to browse entities</p>
      </div>
    )
  }

  return (
    <div className="ent-split" style={{ padding: 0, overflow: 'hidden', height: '100%' }}>
      <EntityListPane
        entityListData={entityListData}
        entityConfig={entityConfig}
        selectedEntity={selectedEntity}
        entityFilter={entityFilter}
        onFilterChange={setEntityFilter}
        onSelectEntity={handleSelectEntity}
        onRefresh={fetchEntityList}
      />
      <EntityInspectorPane
        entity={selectedEntity}
        entityListData={entityListData}
        onFollowEntity={handleSelectEntity}
      />
    </div>
  )
}
