import { useState, type ReactNode } from 'react'

interface EntityInspectorSectionProps {
  groupName: string
  fieldCount: number
  defaultCollapsed?: boolean
  hidden?: boolean
  children: ReactNode
}

export function EntityInspectorSection({
  groupName,
  fieldCount,
  defaultCollapsed = false,
  hidden = false,
  children,
}: EntityInspectorSectionProps) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed)

  return (
    <div
      className={'insp-section' + (hidden ? ' hidden-by-filter' : '')}
      data-section-name={groupName}
    >
      <div className="insp-section-hdr" onClick={() => setCollapsed(!collapsed)}>
        <span className={'insp-section-arrow' + (collapsed ? ' collapsed' : '')}>
          {'\u25BE'}
        </span>
        {groupName}
        <span
          style={{
            fontWeight: 400,
            color: 'var(--t3)',
            fontSize: '.75rem',
            marginLeft: 4,
          }}
        >
          {' '}
          ({fieldCount})
        </span>
      </div>
      <div className="insp-section-body" style={{ display: collapsed ? 'none' : undefined }}>
        {children}
      </div>
    </div>
  )
}
