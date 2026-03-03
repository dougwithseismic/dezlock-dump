import { createContext, useContext, useState, useCallback, useMemo, type ReactNode } from 'react'
import type {
  SchemaData,
  ClassMapEntry,
  EnumMapEntry,
  ProtoMapEntry,
  SearchEntry,
  SidebarItem,
} from '../types/schema'

interface SchemaState {
  D: SchemaData
  classMap: Map<string, ClassMapEntry>
  enumMap: Map<string, EnumMapEntry>
  childrenMap: Map<string, string[]>
  rootClasses: string[]
  moduleNames: string[]
  searchEntries: SearchEntry[]
  allClasses: SidebarItem[]
  allEnums: SidebarItem[]
  allProtoMessages: SidebarItem[]
  protoMap: Map<string, ProtoMapEntry>
}

interface SchemaContextValue extends Omit<SchemaState, 'D'> {
  D: SchemaData | null
  moduleFilter: Set<string>
  setModuleFilter: (filter: Set<string>) => void
  loadData: (raw: SchemaData) => void
  resolveClassMod: (name: string, preferMod?: string) => string | null
}

const SchemaContext = createContext<SchemaContextValue>({
  D: null,
  classMap: new Map(),
  enumMap: new Map(),
  childrenMap: new Map(),
  rootClasses: [],
  moduleNames: [],
  moduleFilter: new Set(),
  setModuleFilter: () => {},
  searchEntries: [],
  allClasses: [],
  allEnums: [],
  allProtoMessages: [],
  protoMap: new Map(),
  loadData: () => {},
  resolveClassMod: () => null,
})

export function SchemaProvider({ children }: { children: ReactNode }) {
  const [schema, setSchema] = useState<SchemaState | null>(null)
  const [moduleFilter, setModuleFilter] = useState<Set<string>>(new Set())

  const loadData = useCallback((raw: SchemaData) => {
    const cMap = new Map<string, ClassMapEntry>()
    const eMap = new Map<string, EnumMapEntry>()
    const chMap = new Map<string, string[]>()
    const roots: string[] = []
    const modNames: string[] = []
    const sEntries: SearchEntry[] = []
    const aC: SidebarItem[] = []
    const aE: SidebarItem[] = []
    const aPb: SidebarItem[] = []
    const pMap = new Map<string, ProtoMapEntry>()

    const isHigherPriority = (a: string, b: string): boolean =>
      a.toLowerCase() === 'client.dll' && b.toLowerCase() === 'server.dll'

    const mods = raw.modules || []
    for (const mod of mods) {
      const mn = mod.name
      modNames.push(mn)

      for (const c of mod.classes || []) {
        if (!cMap.has(c.name)) {
          cMap.set(c.name, { m: mn, o: c, mods: [mn], perMod: { [mn]: c } })
        } else {
          const ex = cMap.get(c.name)!
          if (!ex.mods.includes(mn)) ex.mods.push(mn)
          ex.perMod[mn] = c
          if (isHigherPriority(mn, ex.m)) {
            ex.m = mn
            ex.o = c
          }
        }
        aC.push({ n: c.name, m: mn })
        sEntries.push({ name: c.name, category: 'c', module: mn, context: null })

        if (c.parent) {
          if (!chMap.has(c.parent)) chMap.set(c.parent, [])
          chMap.get(c.parent)!.push(c.name)
        } else {
          roots.push(c.name)
        }

        for (const f of c.fields || []) {
          sEntries.push({ name: f.name, category: 'f', module: mn, context: c.name })
        }
      }

      for (const e of mod.enums || []) {
        if (!eMap.has(e.name)) {
          eMap.set(e.name, { m: mn, o: e, mods: [mn], perMod: { [mn]: e } })
        } else {
          const ex = eMap.get(e.name)!
          if (!ex.mods.includes(mn)) ex.mods.push(mn)
          ex.perMod[mn] = e
          if (isHigherPriority(mn, ex.m)) {
            ex.m = mn
            ex.o = e
          }
        }
        aE.push({ n: e.name, m: mn })
        sEntries.push({ name: e.name, category: 'e', module: mn, context: null })
        for (const v of e.values || []) {
          sEntries.push({ name: v.name, category: 'v', module: mn, context: e.name })
        }
      }
    }

    // Globals
    const globs = raw.globals || {}
    for (const mn in globs) {
      for (const g of globs[mn]) {
        sEntries.push({ name: g.class, category: 'g', module: mn, context: null })
      }
    }

    // Protobuf
    const pbm = raw.protobuf_messages || {}
    for (const mn in pbm) {
      for (const pf of pbm[mn].files || []) {
        for (const msg of pf.messages || []) {
          pMap.set(msg.name, { m: mn, f: pf.name, o: msg })
          aPb.push({ n: msg.name, m: mn })
          sEntries.push({ name: msg.name, category: 'pb', module: mn, context: pf.name })
        }
      }
    }

    modNames.sort()
    roots.sort()

    setSchema({
      D: raw,
      classMap: cMap,
      enumMap: eMap,
      childrenMap: chMap,
      rootClasses: roots,
      moduleNames: modNames,
      searchEntries: sEntries,
      allClasses: aC,
      allEnums: aE,
      allProtoMessages: aPb,
      protoMap: pMap,
    })
    const hasClient = modNames.some(m => m.toLowerCase() === 'client.dll')
    const defaultFilter = hasClient
      ? new Set(modNames.filter(m => m.toLowerCase() !== 'server.dll'))
      : new Set(modNames)
    setModuleFilter(defaultFilter)
  }, [])

  const classMap = schema?.classMap ?? new Map<string, ClassMapEntry>()

  const resolveClassMod = useCallback(
    (name: string, preferMod?: string): string | null => {
      const e = classMap.get(name)
      if (!e) return null
      if (preferMod && e.mods.includes(preferMod)) return preferMod
      return e.m
    },
    [classMap],
  )

  const value = useMemo<SchemaContextValue>(
    () => ({
      D: schema?.D ?? null,
      classMap: schema?.classMap ?? new Map(),
      enumMap: schema?.enumMap ?? new Map(),
      childrenMap: schema?.childrenMap ?? new Map(),
      rootClasses: schema?.rootClasses ?? [],
      moduleNames: schema?.moduleNames ?? [],
      moduleFilter,
      setModuleFilter,
      searchEntries: schema?.searchEntries ?? [],
      allClasses: schema?.allClasses ?? [],
      allEnums: schema?.allEnums ?? [],
      allProtoMessages: schema?.allProtoMessages ?? [],
      protoMap: schema?.protoMap ?? new Map(),
      loadData,
      resolveClassMod,
    }),
    [schema, moduleFilter, loadData, resolveClassMod],
  )

  return <SchemaContext.Provider value={value}>{children}</SchemaContext.Provider>
}

export function useSchema() {
  return useContext(SchemaContext)
}
