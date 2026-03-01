import { useRef, useCallback, useEffect } from 'react'

interface ColumnResizeHandleProps {
  containerRef: React.RefObject<HTMLDivElement | null>
}

export function ColumnResizeHandle({ containerRef }: ColumnResizeHandleProps) {
  const dragging = useRef(false)
  const startX = useRef(0)
  const startW = useRef(0)
  const handleRef = useRef<HTMLDivElement>(null)

  const onMove = useCallback(
    (e: MouseEvent) => {
      if (!dragging.current || !containerRef.current) return
      const newW = Math.max(80, startW.current + (e.clientX - startX.current))
      containerRef.current.style.setProperty('--val-col-w', newW + 'px')
    },
    [containerRef],
  )

  const onUp = useCallback(
    (e: MouseEvent) => {
      if (!dragging.current) return
      dragging.current = false
      handleRef.current?.classList.remove('dragging')
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
      const finalW = Math.max(80, startW.current + (e.clientX - startX.current))
      localStorage.setItem('ent-insp-val-col', String(Math.round(finalW)))
    },
    [onMove],
  )

  const onDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault()
      dragging.current = true
      startX.current = e.clientX
      const valEl = handleRef.current?.parentElement
      startW.current = valEl ? valEl.getBoundingClientRect().width : 200
      handleRef.current?.classList.add('dragging')
      document.addEventListener('mousemove', onMove)
      document.addEventListener('mouseup', onUp)
    },
    [onMove, onUp],
  )

  useEffect(() => {
    return () => {
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
    }
  }, [onMove, onUp])

  return <div ref={handleRef} className="insp-col-resize" onMouseDown={onDown} />
}
