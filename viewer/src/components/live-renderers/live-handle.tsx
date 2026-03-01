interface LiveHandleProps {
  value: unknown
}

export function LiveHandle({ value }: LiveHandleProps) {
  // Rich typed object from server with _t='handle'
  if (value && typeof value === 'object' && '_t' in value) {
    const v = value as { _t: string; index?: number; serial?: number; raw?: number; type?: string }
    return (
      <>
        <span
          className="live-handle"
          title={
            'Click to follow entity. Type: ' +
            (v.type || 'unknown') +
            '. Raw: 0x' +
            ((v.raw ?? 0) >>> 0).toString(16).toUpperCase()
          }
        >
          ent:{v.index} seq:{v.serial}
        </span>
        {v.type && (
          <span className="badge" style={{ marginLeft: 4 }}>
            {v.type}
          </span>
        )}
      </>
    )
  }

  // Bare numeric value — parse handle components
  const raw = typeof value === 'number' ? value : parseInt(String(value), 10)
  const index = raw & 0x7fff
  const serial = (raw >>> 15) & 0x1ffff

  return (
    <span
      className="live-handle"
      title={'Click to follow entity. Raw: 0x' + (raw >>> 0).toString(16).toUpperCase()}
    >
      ent:{index} seq:{serial}
    </span>
  )
}
