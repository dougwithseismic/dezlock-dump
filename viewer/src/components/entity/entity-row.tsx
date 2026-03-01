import { memo } from 'react'
import type { EntityListItem } from '../../types/entity'

interface EntityRowProps {
  entity: EntityListItem
  selected: boolean
  style?: React.CSSProperties
}

export const EntityRow = memo(function EntityRow({ entity, selected, style }: EntityRowProps) {
  return (
    <div className={'ent-row' + (selected ? ' selected' : '')} data-addr={entity.addr} style={style}>
      <div className="ent-row-cell ent-row-idx">{String(entity.index)}</div>
      <div className="ent-row-cell ent-row-cls">
        {entity.class}
        {entity.designer_name && (
          <span style={{ color: 'var(--t3)', fontSize: '11px' }}>
            {' '}
            {entity.designer_name}
          </span>
        )}
      </div>
      <div className="ent-row-cell ent-row-addr">{entity.addr}</div>
    </div>
  )
})
