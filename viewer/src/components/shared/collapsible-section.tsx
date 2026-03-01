import { useState, type ReactNode } from 'react'

interface CollapsibleSectionProps {
  title: string
  count?: number | string
  defaultOpen?: boolean
  children: ReactNode
}

export function CollapsibleSection({ title, count, defaultOpen = true, children }: CollapsibleSectionProps) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div>
      <div className="gl-mhdr" onClick={() => setOpen((p) => !p)} style={{ cursor: 'pointer' }}>
        <span className={'gl-arrow' + (open ? '' : ' collapsed')}>{'\u25B6'}</span>
        <span className="gl-mname">{title}</span>
        {count != null && <span className="gl-mcnt">({String(count)})</span>}
      </div>
      <div style={{ display: open ? '' : 'none' }}>{children}</div>
    </div>
  )
}
