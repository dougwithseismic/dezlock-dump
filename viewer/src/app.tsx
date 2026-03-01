import { useState, useRef, useCallback } from 'react'
import { useSchema } from './context/schema-context'
import { useLive } from './context/live-context'
import { EntityProvider } from './context/entity-context'
import { useHashRouter } from './hooks/use-hash-router'
import { useKeyboardShortcuts } from './hooks/use-keyboard-shortcuts'
import { LandingPage } from './components/landing/landing-page'
import { AppHeader } from './components/layout/app-header'
import { AppSidebar } from './components/layout/app-sidebar'
import { TabBar } from './components/layout/tab-bar'
import { ConsoleDrawer } from './components/layout/console-drawer'
import { MobileSidebarToggle } from './components/layout/mobile-sidebar-toggle'
import { ClassView } from './components/views/class-view'
import { EnumView } from './components/views/enum-view'
import { GlobalsView } from './components/views/globals-view'
import { GlobalDetailView } from './components/views/global-detail-view'
import { TreeView } from './components/views/tree-view'
import { ProtobufView } from './components/views/protobuf-view'
import { ProtobufDetailView } from './components/views/protobuf-detail-view'
import { EntityView } from './components/views/entity-view'
import { EmptyView } from './components/views/empty-view'
import type { TabName } from './lib/constants'

export function App() {
  const { D } = useSchema()
  const { connected } = useLive()
  const { route, navigate } = useHashRouter()
  const [activeTab, setActiveTab] = useState<TabName>('classes')
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [consoleOpen, setConsoleOpen] = useState(false)
  const searchInputRef = useRef<HTMLInputElement>(null)

  // Sync tab from hash route
  const effectiveTab = (() => {
    if (!route.type) return activeTab
    if (route.type === 'class') return 'classes'
    if (route.type === 'enum') return 'enums'
    if (route.type === 'global' || route.type === 'globals') return 'globals'
    if (route.type === 'tree') return 'tree'
    if (route.type === 'protobuf') return 'protobuf'
    if (route.type === 'entities') return 'entities'
    return activeTab
  })()

  const handleTabChange = useCallback(
    (tab: TabName) => {
      setActiveTab(tab)
      if (tab === 'globals') navigate('globals')
      else if (tab === 'tree') navigate('tree')
      else if (tab === 'entities') navigate('entities')
      else if (tab === 'protobuf') navigate('protobuf')
      else {
        // Clear hash so effectiveTab falls back to activeTab state
        history.replaceState(null, '', location.pathname)
        window.dispatchEvent(new HashChangeEvent('hashchange'))
      }
    },
    [navigate],
  )

  useKeyboardShortcuts({
    onSearch: () => searchInputRef.current?.focus(),
    onEscape: () => {
      setSidebarOpen(false)
      if (consoleOpen) setConsoleOpen(false)
    },
    onToggleConsole: () => setConsoleOpen((p) => !p),
  })

  if (!D) {
    return <LandingPage />
  }

  const renderContent = () => {
    if (effectiveTab === 'entities') {
      return <EntityView />
    }
    if (effectiveTab === 'globals') {
      if (route.type === 'global' && route.name) {
        return <GlobalDetailView name={route.name} module={route.module} />
      }
      return <GlobalsView />
    }
    if (effectiveTab === 'tree') return <TreeView />
    if (effectiveTab === 'protobuf') {
      if (route.type === 'protobuf' && route.name) {
        return <ProtobufDetailView name={route.name} />
      }
      return <ProtobufView />
    }
    if (route.type === 'class' && route.name) {
      return <ClassView name={route.name} module={route.module} />
    }
    if (route.type === 'enum' && route.name) {
      return <EnumView name={route.name} />
    }
    return <EmptyView />
  }

  return (
    <div className="flex flex-col h-screen" style={{ background: 'var(--bg0)' }}>
      <AppHeader />
      <EntityProvider>
        <div className="flex flex-1 overflow-hidden relative">
          <AppSidebar
            activeTab={effectiveTab}
            open={sidebarOpen}
            onClose={() => setSidebarOpen(false)}
            searchInputRef={searchInputRef}
          />
          <MobileSidebarToggle onClick={() => setSidebarOpen((p) => !p)} />
          <main className="flex-1 flex flex-col overflow-hidden">
            <TabBar activeTab={effectiveTab} onTabChange={handleTabChange} showEntities={connected} />
            <div
              className="flex-1 overflow-y-auto"
              style={{ padding: '16px 20px' }}
            >
              {renderContent()}
            </div>
          </main>
        </div>
      </EntityProvider>
      <ConsoleDrawer open={consoleOpen} onToggle={() => setConsoleOpen((p) => !p)} />
      {!consoleOpen && D && (
        <div
          className="fixed bottom-0 left-1/2 -translate-x-1/2 cursor-pointer z-50"
          style={{
            padding: '2px 16px',
            fontSize: '.7rem',
            color: 'var(--t3)',
            background: 'var(--bg2)',
            border: '1px solid var(--brd)',
            borderBottom: 'none',
            borderRadius: '4px 4px 0 0',
          }}
          onClick={() => setConsoleOpen(true)}
        >
          Console
        </div>
      )}
    </div>
  )
}
