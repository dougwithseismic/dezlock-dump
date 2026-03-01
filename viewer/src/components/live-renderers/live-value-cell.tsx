import { liveEditorType } from '../../lib/format'
import { LiveBool } from './live-bool'
import { LiveColor } from './live-color'
import { LiveVector } from './live-vector'
import { LiveFloat } from './live-float'
import { LiveInt } from './live-int'
import { LiveEnum } from './live-enum'
import { LivePointer } from './live-pointer'
import { LiveHandle } from './live-handle'
import { LiveString } from './live-string'
import { LiveStruct } from './live-struct'
import { LiveArray } from './live-array'

interface LiveValueCellProps {
  fieldType: string
  value: unknown
  enumMap?: Map<string, { o: { items?: { name: string; value: number }[] } }>
  classMap?: Map<string, unknown>
  selectedEntityAddr?: string
  fieldOffset?: number
}

export function LiveValueCell({
  fieldType,
  value,
  enumMap,
  classMap,
  selectedEntityAddr,
  fieldOffset,
}: LiveValueCellProps) {
  if (value === null || value === undefined) return <>{'\u2014'}</>

  // Rich typed objects from server (discriminator-based)
  if (value && typeof value === 'object' && '_t' in value) {
    const v = value as { _t: string }
    switch (v._t) {
      case 'enum':
        return <LiveEnum value={value} />
      case 'struct':
        return (
          <LiveStruct
            value={value}
            selectedEntityAddr={selectedEntityAddr}
            fieldOffset={fieldOffset}
          />
        )
      case 'vector':
        return <LiveArray value={value} />
      case 'array':
        return <LiveArray value={value} />
      case 'ptr':
        return <LivePointer value={value} />
      case 'handle':
        return <LiveHandle value={value} />
      case 'string':
        return <LiveString value={value} />
    }
  }

  // Legacy string objects from server: { str, ptr, type }
  if (value && typeof value === 'object' && 'str' in value) {
    const v = value as { str?: string; ptr?: string }
    return (
      <>
        {v.str !== undefined && (
          <span className="live-str" title={v.ptr ? 'Pointer: ' + v.ptr : ''}>
            "{v.str}"
          </span>
        )}
        {v.ptr && <span className="live-str-ptr">{v.ptr}</span>}
      </>
    )
  }

  // Bare primitives
  const edType = liveEditorType(fieldType, enumMap, classMap)

  if (edType === 'bool') return <LiveBool value={value} />
  if (edType === 'color' && Array.isArray(value)) return <LiveColor value={value as number[]} />
  if (edType === 'vector' && Array.isArray(value)) return <LiveVector value={value as number[]} />
  if (edType === 'float') return <LiveFloat value={value as number} />
  if (edType === 'int') return <LiveInt value={value as number} />
  if (edType === 'enum') return <LiveEnum value={value} fieldType={fieldType} enumMap={enumMap} />
  if (edType === 'handle') return <LiveHandle value={value} />
  if (edType === 'pointer') return <LivePointer value={value} />
  if (edType === 'struct') {
    return (
      <LiveStruct
        value={value}
        selectedEntityAddr={selectedEntityAddr}
        fieldOffset={fieldOffset}
      />
    )
  }

  // Fallback text
  const display =
    typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value)
  return <span title={display}>{display}</span>
}
