interface LiveStringProps {
  value: unknown
}

export function LiveString({ value }: LiveStringProps) {
  if (!value || typeof value !== 'object') return <span>{'\u2014'}</span>

  const v = value as { str?: string; ptr?: string }

  if (!v.str && !v.ptr) return <span>{'\u2014'}</span>

  return (
    <>
      {v.str && (
        <span className="live-str" title={v.ptr ? 'Pointer: ' + v.ptr : ''}>
          "{v.str}"
        </span>
      )}
      {v.ptr && <span className="live-str-ptr">{v.ptr}</span>}
    </>
  )
}
