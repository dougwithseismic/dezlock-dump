export interface Field {
  name: string
  type: string
  offset: number
  size: number | null
  metadata?: string[]
  definedIn?: string
}

export interface ClassInfo {
  name: string
  size: number
  parent: string | null
  inheritance?: string[]
  fields?: Field[]
  static_fields?: Field[]
  metadata?: string[]
  components?: { name: string; offset: number }[]
  _flat?: FlatField[]
}

export interface FlatField extends Field {
  definedIn: string
}

export interface EnumValue {
  name: string
  value: number
}

export interface EnumInfo {
  name: string
  size: number
  values?: EnumValue[]
}

export interface GlobalInfo {
  class: string
  rva: string
  vtable_rva: string
  type: 'pointer' | 'static' | string
  has_schema: boolean
  function_count?: number
  parent?: string
  inheritance?: string[]
}

export interface PatternGlobal {
  rva: string
  mode?: string
}

export interface VtableFunction {
  rva: string
  signature?: string
  bytes?: string
}

export interface Vtable {
  name: string
  rva: string
  functions?: VtableFunction[]
}

export interface Module {
  name: string
  classes?: ClassInfo[]
  enums?: EnumInfo[]
  vtables?: Vtable[]
}

export interface SchemaData {
  modules: Module[]
  globals?: Record<string, GlobalInfo[]>
  pattern_globals?: Record<string, Record<string, PatternGlobal>>
  protobuf_messages?: Record<string, ProtoModule>
  total_classes?: number
  total_fields?: number
  total_enums?: number
}

export interface ProtoModule {
  files: ProtoFile[]
}

export interface ProtoFile {
  name: string
  package?: string
  messages?: ProtoMessage[]
}

export interface ProtoMessage {
  name: string
  fields?: ProtoField[]
  nested_messages?: ProtoMessage[]
  nested_enums?: ProtoEnum[]
  oneof_decls?: string[]
}

export interface ProtoField {
  name: string
  number: number
  type: string
  type_name?: string
  label?: string
  oneof_index?: number | null
}

export interface ProtoEnum {
  name: string
  values?: { name: string; number: number }[]
}

export interface ClassMapEntry {
  m: string
  o: ClassInfo
  mods: string[]
  perMod: Record<string, ClassInfo>
}

export interface EnumMapEntry {
  m: string
  o: EnumInfo
  mods: string[]
  perMod: Record<string, EnumInfo>
}

export interface ProtoMapEntry {
  m: string
  f: string
  o: ProtoMessage
}

export interface SearchEntry {
  name: string
  category: SearchCategory
  module: string
  context: string | null
}

export type SearchCategory = 'c' | 'e' | 'f' | 'v' | 'g' | 'pb'

export interface SidebarItem {
  n: string
  m: string
}
