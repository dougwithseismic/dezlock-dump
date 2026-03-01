export type TabName = 'classes' | 'enums' | 'globals' | 'tree' | 'protobuf' | 'entities'

export const TAB_LABELS: Record<TabName, string> = {
  classes: 'Classes',
  enums: 'Enums',
  globals: 'Globals',
  tree: 'Tree',
  protobuf: 'Protobuf',
  entities: 'Entities',
}

export type CategoryCode = 'c' | 'e' | 'f' | 'v' | 'g' | 'pb'

export const CATEGORY_LABELS: Record<CategoryCode, string> = {
  c: 'Classes',
  e: 'Enums',
  f: 'Fields',
  v: 'Enum Values',
  g: 'Globals',
  pb: 'Protobuf',
}

export const CATEGORY_ICONS: Record<CategoryCode, string> = {
  c: 'C',
  e: 'E',
  f: 'F',
  v: 'V',
  g: 'G',
  pb: 'PB',
}

export const CATEGORY_ICON_CLASSES: Record<CategoryCode, string> = {
  c: 'sb-icon-c',
  e: 'sb-icon-e',
  f: 'sb-icon-f',
  v: 'sb-icon-f',
  g: 'sb-icon-g',
  pb: 'sb-icon-pb',
}

export type EditorType =
  | 'bool'
  | 'color'
  | 'vector'
  | 'float'
  | 'int'
  | 'enum'
  | 'handle'
  | 'pointer'
  | 'struct'
  | 'text'

export const SEARCH_ORDER: CategoryCode[] = ['c', 'e', 'f', 'v', 'g', 'pb']

export const DEFAULT_WS_URL = 'ws://127.0.0.1:9100'
