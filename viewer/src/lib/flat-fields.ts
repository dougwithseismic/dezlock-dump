import type { ClassMapEntry, FlatField } from '../types/schema'

export function flatFields(
  name: string,
  classMap: Map<string, ClassMapEntry>,
): FlatField[] {
  const e = classMap.get(name)
  if (!e) return []
  if (e.o._flat) return e.o._flat

  const fields: FlatField[] = []
  const visited = new Set<string>()

  function collect(n: string) {
    if (visited.has(n)) return
    visited.add(n)
    const x = classMap.get(n)
    if (!x) return
    for (const f of x.o.fields || []) {
      fields.push({ ...f, definedIn: n })
    }
    if (x.o.parent) collect(x.o.parent)
  }

  collect(name)
  fields.sort((a, b) => a.offset - b.offset)
  e.o._flat = fields
  return fields
}
