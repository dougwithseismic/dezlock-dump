import { useCallback, useRef, useState, useEffect, type RefObject } from 'react'
import { SidebarSearch } from './sidebar-search'
import { ModuleFilter } from './module-filter'
import { SidebarList } from './sidebar-list'
import type { TabName } from '../../lib/constants'

interface AppSidebarProps {
  activeTab: TabName
  open: boolean
  onClose: () => void
  searchInputRef: RefObject<HTMLInputElement | null>
}

export function AppSidebar({ activeTab, open, onClose, searchInputRef }: AppSidebarProps) {
  const sidebarRef = useRef<HTMLDivElement>(null)
  const [listHeight, setListHeight] = useState(400)

  useEffect(() => {
    const updateHeight = () => {
      if (!sidebarRef.current) return
      const sidebar = sidebarRef.current
      const searchEl = sidebar.querySelector('[data-sidebar-search]') as HTMLElement | null
      const filterEl = sidebar.querySelector('[data-sidebar-filter]') as HTMLElement | null
      const searchH = searchEl?.offsetHeight ?? 0
      const filterH = filterEl?.offsetHeight ?? 0
      const available = sidebar.clientHeight - searchH - filterH
      setListHeight(Math.max(100, available))
    }
    updateHeight()
    window.addEventListener('resize', updateHeight)
    const observer = new ResizeObserver(updateHeight)
    if (sidebarRef.current) {
      observer.observe(sidebarRef.current)
    }
    return () => {
      window.removeEventListener('resize', updateHeight)
      observer.disconnect()
    }
  }, [])

  const handleSelect = useCallback(() => {
    onClose()
  }, [onClose])

  return (
    <>
      {/* Backdrop for mobile */}
      {open && (
        <div
          className="fixed inset-0 z-40 md:hidden"
          style={{ background: 'rgba(0,0,0,.5)' }}
          onClick={onClose}
        />
      )}
      <aside
        ref={sidebarRef}
        className={`flex flex-col shrink-0 overflow-hidden z-50
          fixed inset-y-0 left-0 transition-transform md:relative md:translate-x-0
          ${open ? 'translate-x-0' : '-translate-x-full'}`}
        style={{
          width: 'var(--side)',
          background: 'var(--bg1)',
          borderRight: '1px solid var(--brd)',
          top: 'var(--hdr)',
        }}
      >
        <div data-sidebar-search>
          <SidebarSearch searchInputRef={searchInputRef} onSelect={handleSelect} />
        </div>
        <div data-sidebar-filter>
          <ModuleFilter />
        </div>
        <SidebarList activeTab={activeTab} height={listHeight} />
      </aside>
    </>
  )
}
