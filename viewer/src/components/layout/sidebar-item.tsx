import { memo } from 'react'
import type { CategoryCode } from '../../lib/constants'
import { CATEGORY_ICONS } from '../../lib/constants'

interface SidebarItemProps {
  name: string
  module: string
  category: CategoryCode
  active: boolean
  onClick: () => void
  style?: React.CSSProperties
}

const ICON_COLORS: Record<CategoryCode, string> = {
  c: 'var(--acc)',
  e: 'var(--warn)',
  g: 'var(--ok)',
  f: 'var(--link)',
  v: 'var(--link)',
  pb: '#a371f7',
}

export const SidebarItemRow = memo(function SidebarItemRow({
  name,
  module,
  category,
  active,
  onClick,
  style,
}: SidebarItemProps) {
  return (
    <div
      className="flex items-center gap-2 px-3 cursor-pointer"
      style={{
        ...style,
        height: 28,
        background: active ? 'var(--bg-a)' : 'transparent',
        color: 'var(--t1)',
      }}
      onClick={onClick}
      onMouseEnter={(e) => {
        if (!active) (e.currentTarget as HTMLElement).style.background = 'var(--bg-h)'
      }}
      onMouseLeave={(e) => {
        if (!active) (e.currentTarget as HTMLElement).style.background = 'transparent'
      }}
    >
      <span
        className="flex items-center justify-center text-xs font-bold rounded shrink-0"
        style={{
          width: 20,
          height: 20,
          color: ICON_COLORS[category] || 'var(--t2)',
          background: 'var(--bg2)',
          fontSize: category === 'pb' ? '.6rem' : '.7rem',
        }}
      >
        {CATEGORY_ICONS[category]}
      </span>
      <span className="truncate text-sm" style={{ fontFamily: 'var(--mono)' }}>
        {name}
      </span>
      <span
        className="ml-auto text-xs shrink-0 px-1.5 rounded"
        style={{ background: 'var(--badge)', color: 'var(--badge-t)', fontSize: '.65rem' }}
      >
        {module.replace('.dll', '')}
      </span>
    </div>
  )
})
