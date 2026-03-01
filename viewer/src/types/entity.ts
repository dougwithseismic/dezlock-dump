export interface EntityListItem {
  index: number
  class: string
  addr: string
  designer_name?: string
}

export interface EntityConfig {
  probed: boolean
  identity_stride: number
  chunk_offset: number
  max_chunks: number
  chunk_size: number
  designer_name_offset: number
  ges_addr: string
}

export interface EntitySearchMatch {
  entity_index: number
  class: string
  addr: string
  field_name: string
  field_value: unknown
}

export interface EntitySearchResult {
  matches: EntitySearchMatch[]
  count: number
}

export interface DerefResult {
  kind: 'string' | 'object' | 'raw'
  value?: string
  class?: string
  addr?: string
  fields?: Record<string, unknown>
  hex?: string
}
