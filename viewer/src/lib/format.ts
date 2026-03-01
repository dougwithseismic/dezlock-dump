/** Format number as hex with padding */
export function h(v: number | null | undefined, d = 3): string {
  if (v == null) return '\u2014'
  const s = v.toString(16).toUpperCase()
  return '0x' + s.padStart(d, '0')
}

/** Ensure string has 0x prefix */
export function hs(s: string | null | undefined): string {
  if (!s) return '\u2014'
  return s.startsWith('0x') ? s : '0x' + s
}

/** Format number with locale separators */
export function fnum(n: number | null | undefined): string {
  return n != null ? n.toLocaleString('en-US') : '0'
}

/** Extract inner class/type name from a field type string */
export function extractType(t: string | null | undefined): string | null {
  if (!t) return null
  let n = t.replace(/[*&\s]+$/g, '').trim()
  const m = n.match(/^[A-Za-z_]\w*<\s*([A-Za-z_]\w*)\s*>$/)
  if (m) n = m[1]
  n = n.replace(/\[\d*\]$/, '').trim()
  return /^[A-Z]/.test(n) && n.length > 1 ? n : null
}

/** Determine live editor type from field type string */
export function liveEditorType(
  fieldType: string | null | undefined,
  enumMap?: Map<string, unknown>,
  classMap?: Map<string, unknown>,
): string {
  if (!fieldType) return 'text'
  const t = fieldType.replace(/\s/g, '')
  if (t === 'bool') return 'bool'
  if (t === 'Color') return 'color'
  if (/^(Vector[24]?D?|QAngle|Vector4D|Quaternion)$/i.test(t)) return 'vector'
  if (/^CHandle</.test(t)) return 'handle'
  if (/^(CUtlString|CUtlSymbolLarge)$/.test(t)) return 'pointer'
  if (/^float(32|64)?$/.test(t)) return 'float'
  if (/^(u?int(8|16|32|64)|char|short|long|bool)$/.test(t)) return 'int'
  if (enumMap && enumMap.has(t)) return 'enum'
  if (classMap && classMap.has(t)) return 'struct'
  return 'text'
}
