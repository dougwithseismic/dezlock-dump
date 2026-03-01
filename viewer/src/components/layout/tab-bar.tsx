import { TAB_LABELS, type TabName } from '../../lib/constants'

interface TabBarProps {
  activeTab: TabName
  onTabChange: (tab: TabName) => void
  showEntities: boolean
}

const TAB_ORDER: TabName[] = ['classes', 'enums', 'globals', 'tree', 'protobuf', 'entities']

export function TabBar({ activeTab, onTabChange, showEntities }: TabBarProps) {
  return (
    <nav
      className="flex shrink-0 overflow-x-auto"
      style={{
        borderBottom: '1px solid var(--brd)',
        background: 'var(--bg1)',
      }}
    >
      {TAB_ORDER.map((tab) => {
        if (tab === 'entities' && !showEntities) return null
        const active = activeTab === tab
        return (
          <button
            key={tab}
            onClick={() => onTabChange(tab)}
            className="px-4 py-2 text-sm cursor-pointer whitespace-nowrap"
            style={{
              background: 'transparent',
              color: active ? 'var(--acc)' : 'var(--t2)',
              border: 'none',
              borderBottom: active ? '2px solid var(--acc)' : '2px solid transparent',
              fontWeight: active ? 600 : 400,
            }}
          >
            {TAB_LABELS[tab]}
          </button>
        )
      })}
    </nav>
  )
}
