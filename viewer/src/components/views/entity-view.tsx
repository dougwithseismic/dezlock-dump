import { useLive } from '../../context/live-context'
import { useEntity } from '../../context/entity-context'
import { EntityInspectorPane } from '../entity/entity-inspector-pane'

export function EntityView() {
  const { connected } = useLive()
  const { selectedEntity, entityListData, selectEntity } = useEntity()

  if (!connected) {
    return (
      <div className="empty">
        <p>Connect live to browse entities</p>
      </div>
    )
  }

  return (
    <EntityInspectorPane
      entity={selectedEntity}
      entityListData={entityListData}
      onFollowEntity={selectEntity}
    />
  )
}
