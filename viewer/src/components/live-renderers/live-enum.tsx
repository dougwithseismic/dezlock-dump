interface LiveEnumProps {
  value: unknown
  fieldType?: string
  enumMap?: Map<string, { o: { items?: { name: string; value: number }[] } }>
}

export function LiveEnum({ value, fieldType, enumMap }: LiveEnumProps) {
  // Rich typed object from server with _t='enum'
  if (value && typeof value === 'object' && '_t' in value) {
    const v = value as { _t: string; name?: string; v?: number; raw_value?: number; enum?: string; type?: string }
    const rawVal = v.v ?? v.raw_value
    const enumType = v.enum || v.type

    return (
      <>
        {v.name ? (
          <>
            <span className="live-enum">{v.name}</span>
            <span className="live-enum-raw"> ({rawVal})</span>
          </>
        ) : (
          <span className="live-enum" title={enumType || ''}>
            {String(rawVal)}
          </span>
        )}
        {enumType && <span className="badge live-enum-type">{enumType}</span>}
      </>
    )
  }

  // Bare numeric value + fieldType for resolution via enumMap
  const enumName = fieldType ? fieldType.replace(/\s/g, '') : ''
  const enumEntry = enumMap ? enumMap.get(enumName) : null
  const numVal = typeof value === 'number' ? value : parseInt(String(value), 10)

  let resolvedName: string | null = null
  if (enumEntry?.o?.items) {
    for (const item of enumEntry.o.items) {
      if (item.value === numVal) {
        resolvedName = item.name
        break
      }
    }
  }

  return (
    <>
      <span className="live-num-drag" title="Double-click for enum picker">
        {resolvedName ? `${resolvedName} (${numVal})` : String(isNaN(numVal) ? value : numVal)}
      </span>
      {enumName && <span className="live-enum-badge">{enumName}</span>}
    </>
  )
}
