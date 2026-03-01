import type { ReactNode } from 'react'

interface SectionHeaderProps {
  title: string
  count?: number | string
  toggleLabel?: string
  onToggle?: () => void
  children?: ReactNode
}

export function SectionHeader({ title, count, toggleLabel, onToggle, children }: SectionHeaderProps) {
  return (
    <div className="sec-hdr">
      <span className="sec-title">{title}</span>
      {count != null && <span className="sec-count">{String(count)}</span>}
      {toggleLabel && onToggle && (
        <button className="sec-toggle" onClick={onToggle}>
          {toggleLabel}
        </button>
      )}
      {children}
    </div>
  )
}
