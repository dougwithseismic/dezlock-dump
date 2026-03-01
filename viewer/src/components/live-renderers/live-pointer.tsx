interface LivePointerProps {
  value: unknown
}

export function LivePointer({ value }: LivePointerProps) {
  // Rich typed object from server with _t='ptr'
  if (value && typeof value === 'object' && '_t' in value) {
    const v = value as { _t: string; addr?: string; type?: string; valid?: boolean }

    return (
      <>
        <span
          className={'live-ptr' + (v.valid && v.type ? ' insp-drilldown-toggle' : '')}
          title="Click to drill down"
          data-drill-addr={v.valid && v.type ? v.addr : undefined}
          data-drill-type={v.valid && v.type ? v.type : undefined}
        >
          {v.addr || '0x0'}
        </span>
        {v.type && (
          <span className="badge" style={{ marginLeft: 4 }}>
            {v.type}*
          </span>
        )}
        {!v.valid && (
          <span
            className="badge"
            style={{
              marginLeft: 4,
              background: 'var(--err-bg,#3d1f1f)',
              color: 'var(--err,#f85149)',
            }}
          >
            null
          </span>
        )}
      </>
    )
  }

  // Bare string pointer value
  const strVal = String(value)
  return (
    <span
      className="live-ptr insp-drilldown-toggle"
      title="Click to drill down (string pointer)"
      data-drill-addr={strVal}
      data-drill-type=""
    >
      {'\u25B6'} {strVal}
    </span>
  )
}
