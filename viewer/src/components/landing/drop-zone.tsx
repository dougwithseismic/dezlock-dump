import { useRef, useState, useCallback, type DragEvent } from 'react'

interface DropZoneProps {
  onFile: (file: File) => void
}

export function DropZone({ onFile }: DropZoneProps) {
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleDragOver = useCallback((e: DragEvent) => {
    e.preventDefault()
    setDragOver(true)
  }, [])

  const handleDragLeave = useCallback(() => {
    setDragOver(false)
  }, [])

  const handleDrop = useCallback(
    (e: DragEvent) => {
      e.preventDefault()
      setDragOver(false)
      const f = e.dataTransfer.files[0]
      if (f && f.name.endsWith('.json')) onFile(f)
    },
    [onFile],
  )

  const handleClick = useCallback(
    (e: React.MouseEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName !== 'INPUT' && !target.closest('.btn')) {
        fileInputRef.current?.click()
      }
    },
    [],
  )

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const f = e.target.files?.[0]
      if (f) onFile(f)
    },
    [onFile],
  )

  return (
    <div
      className="flex flex-col items-center gap-3 p-10 rounded-lg border-2 border-dashed cursor-pointer transition-colors"
      style={{
        borderColor: dragOver ? 'var(--acc)' : 'var(--brd)',
        background: dragOver ? 'var(--acc-d)' : 'transparent',
      }}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={handleClick}
    >
      <div style={{ color: dragOver ? 'var(--acc)' : 'var(--t3)' }} className="transition-colors">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
          <polyline points="17 8 12 3 7 8" />
          <line x1="12" y1="3" x2="12" y2="15" />
        </svg>
      </div>
      <p style={{ color: 'var(--t2)' }}>
        Drop <code>_all-modules.json</code> here
      </p>
      <p style={{ color: 'var(--t3)', fontSize: '.85rem' }}>or</p>
      <label
        className="btn px-4 py-2 rounded cursor-pointer text-sm"
        style={{ background: 'var(--bg2)', color: 'var(--t1)', border: '1px solid var(--brd)' }}
      >
        Choose File
        <input
          ref={fileInputRef}
          type="file"
          accept=".json"
          hidden
          onChange={handleFileChange}
        />
      </label>
    </div>
  )
}
