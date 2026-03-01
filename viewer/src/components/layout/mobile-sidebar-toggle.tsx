interface MobileSidebarToggleProps {
  onClick: () => void
}

export function MobileSidebarToggle({ onClick }: MobileSidebarToggleProps) {
  return (
    <button
      onClick={onClick}
      className="fixed bottom-4 left-4 z-50 flex items-center justify-center w-10 h-10 rounded-full cursor-pointer md:hidden"
      style={{
        background: 'var(--bg2)',
        color: 'var(--t1)',
        border: '1px solid var(--brd)',
        boxShadow: '0 2px 8px rgba(0,0,0,.3)',
      }}
      title="Toggle sidebar"
    >
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <line x1="3" y1="12" x2="21" y2="12" />
        <line x1="3" y1="6" x2="21" y2="6" />
        <line x1="3" y1="18" x2="21" y2="18" />
      </svg>
    </button>
  )
}
