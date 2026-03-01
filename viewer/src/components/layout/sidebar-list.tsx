import { useMemo, useCallback, type CSSProperties, type ReactElement } from 'react'
import { List } from 'react-window'
import { useSchema } from '../../context/schema-context'
import { useHashRouter } from '../../hooks/use-hash-router'
import { SidebarItemRow } from './sidebar-item'
import { EntitySidebarList } from '../entity/entity-sidebar-list'
import { fnum } from '../../lib/format'
import { CATEGORY_LABELS, type TabName, type CategoryCode } from '../../lib/constants'
import type { SidebarItem } from '../../types/schema'

interface SidebarListProps {
  activeTab: TabName
  height: number
}

interface RowExtraProps {
  items: SidebarItem[]
  category: CategoryCode
  activeModule: string
  activeName: string
  onItemClick: (item: SidebarItem, cat: CategoryCode) => void
}

function SidebarRow({
  index,
  style,
  items,
  category,
  activeModule,
  activeName,
  onItemClick,
}: {
  index: number
  style: CSSProperties
} & RowExtraProps): ReactElement | null {
  const item = items[index]
  if (!item) return null
  return (
    <SidebarItemRow
      style={style}
      name={item.n}
      module={item.m}
      category={category}
      active={activeName === item.n && activeModule === item.m}
      onClick={() => onItemClick(item, category)}
    />
  )
}

export function SidebarList({ activeTab, height }: SidebarListProps) {
  const { D, allClasses, allEnums, allProtoMessages, moduleFilter, classMap } = useSchema()
  const { route, navigate } = useHashRouter()

  const { items, category } = useMemo(() => {
    if (activeTab === 'entities') return { items: [] as SidebarItem[], category: 'c' as CategoryCode }

    let filtered: SidebarItem[] = []
    let cat: CategoryCode = 'c'

    if (activeTab === 'classes' || activeTab === 'tree') {
      filtered = allClasses.filter((c) => moduleFilter.has(c.m))
      cat = 'c'
    } else if (activeTab === 'enums') {
      filtered = allEnums.filter((e) => moduleFilter.has(e.m))
      cat = 'e'
    } else if (activeTab === 'globals') {
      const globs = D?.globals || {}
      const globItems: SidebarItem[] = []
      for (const mn in globs) {
        if (!moduleFilter.has(mn)) continue
        for (const g of globs[mn]) {
          globItems.push({ n: g.class, m: mn })
        }
      }
      filtered = globItems
      cat = 'g'
    } else if (activeTab === 'protobuf') {
      filtered = allProtoMessages.filter((p) => moduleFilter.has(p.m))
      cat = 'pb'
    }

    filtered.sort((a, b) => a.n.localeCompare(b.n))
    return { items: filtered, category: cat }
  }, [activeTab, allClasses, allEnums, allProtoMessages, D, moduleFilter])

  const handleClick = useCallback(
    (item: SidebarItem, cat: CategoryCode) => {
      if (cat === 'pb') navigate('protobuf', item.m, item.n)
      else if (cat === 'g') {
        const ce = classMap.get(item.n)
        if (ce) navigate('class', ce.m, item.n)
        else navigate('global', item.m, item.n)
      }
      else if (cat === 'e') navigate('enum', item.m, item.n)
      else navigate('class', item.m, item.n)
    },
    [navigate, classMap],
  )

  // Entities tab gets its own sidebar component (after all hooks)
  if (activeTab === 'entities') {
    return <EntitySidebarList height={height} />
  }

  if (items.length === 0) {
    return (
      <div className="flex items-center justify-center h-20" style={{ color: 'var(--t3)' }}>
        <p className="text-sm">No items</p>
      </div>
    )
  }

  const headerHeight = 24
  const itemHeight = 28
  const catLabel = CATEGORY_LABELS[category]

  return (
    <div className="flex-1" style={{ minHeight: 0 }}>
      <div
        className="px-3 py-1 text-xs font-semibold"
        style={{ color: 'var(--t3)', height: headerHeight }}
      >
        {catLabel} ({fnum(items.length)})
      </div>
      <List<RowExtraProps>
        rowComponent={SidebarRow}
        rowCount={items.length}
        rowHeight={itemHeight}
        rowProps={{
          items,
          category,
          activeModule: route.module,
          activeName: route.name,
          onItemClick: handleClick,
        } as RowExtraProps}
        style={{ height: Math.max(0, height - headerHeight) }}
      />
    </div>
  )
}
