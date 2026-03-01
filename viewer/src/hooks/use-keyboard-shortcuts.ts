import { useEffect, useRef } from 'react'

interface ShortcutHandlers {
  onSearch?: () => void
  onEscape?: () => void
  onToggleConsole?: () => void
}

export function useKeyboardShortcuts(handlers: ShortcutHandlers) {
  const handlersRef = useRef(handlers)
  handlersRef.current = handlers

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        handlersRef.current.onSearch?.()
      }
      if (e.key === 'Escape') {
        handlersRef.current.onEscape?.()
      }
      if (
        e.key === '`' &&
        !e.ctrlKey &&
        !e.metaKey &&
        (document.activeElement as HTMLElement)?.tagName !== 'INPUT' &&
        (document.activeElement as HTMLElement)?.tagName !== 'TEXTAREA'
      ) {
        e.preventDefault()
        handlersRef.current.onToggleConsole?.()
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])
}
