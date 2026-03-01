import { useState, useCallback, useRef, type RefObject } from 'react'
import { useDebouncedValue } from '../../hooks/use-debounced-value'
import { useSchema } from '../../context/schema-context'
import { useHashRouter } from '../../hooks/use-hash-router'
import { syncSearch } from '../../lib/search'
import { SidebarItemRow } from './sidebar-item'
import {
  CATEGORY_LABELS,
  SEARCH_ORDER,
  type CategoryCode,
} from '../../lib/constants'
import type { SearchEntry } from '../../types/schema'
import { useEffect } from 'react'

interface SidebarSearchProps {
  searchInputRef: RefObject<HTMLInputElement | null>
  onSelect: (type: string, module: string, name: string) => void
}

export function SidebarSearch({ searchInputRef, onSelect }: SidebarSearchProps) {
  const { searchEntries, classMap } = useSchema()
  const { navigate } = useHashRouter()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<SearchEntry[] | null>(null)
  const debouncedQuery = useDebouncedValue(query, 150)

  useEffect(() => {
    if (!debouncedQuery.trim()) {
      setResults(null)
      return
    }
    const searchResults = syncSearch(debouncedQuery, searchEntries)
    const entries = searchResults.map((r) => searchEntries[r.index])
    setResults(entries)
  }, [debouncedQuery, searchEntries])

  const handleClear = useCallback(() => {
    setQuery('')
    setResults(null)
    searchInputRef.current?.focus()
  }, [searchInputRef])

  const handleSelect = useCallback(
    (entry: SearchEntry) => {
      const cat = entry.category
      if (cat === 'c') navigate('class', entry.module, entry.name)
      else if (cat === 'g') {
        const ce = classMap.get(entry.name)
        if (ce) navigate('class', ce.m, entry.name)
        else navigate('global', entry.module, entry.name)
      }
      else if (cat === 'f') navigate('class', entry.module, entry.context!)
      else if (cat === 'e') navigate('enum', entry.module, entry.name)
      else if (cat === 'v') navigate('enum', entry.module, entry.context!)
      else if (cat === 'pb') navigate('protobuf', entry.module, entry.name)
      onSelect(cat, entry.module, entry.name)
    },
    [navigate, onSelect, classMap],
  )

  // Group results by category
  const grouped = results
    ? SEARCH_ORDER.reduce(
        (acc, cat) => {
          const items = results.filter((r) => r.category === cat)
          if (items.length) acc.push({ category: cat, items })
          return acc
        },
        [] as { category: CategoryCode; items: SearchEntry[] }[],
      )
    : null

  return (
    <div>
      <div className="relative px-3 py-2" style={{ borderBottom: '1px solid var(--brd)' }}>
        <input
          ref={searchInputRef}
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search classes, fields, enums... (Ctrl+K)"
          className="w-full px-3 py-1.5 rounded text-sm"
          style={{
            background: 'var(--bg0)',
            color: 'var(--t1)',
            border: '1px solid var(--brd)',
            fontFamily: 'var(--mono)',
          }}
        />
        {query && (
          <button
            onClick={handleClear}
            className="absolute right-5 top-1/2 -translate-y-1/2 text-lg cursor-pointer"
            style={{
              color: 'var(--t3)',
              background: 'none',
              border: 'none',
              lineHeight: 1,
            }}
          >
            &times;
          </button>
        )}
      </div>

      {grouped && (
        <div className="overflow-y-auto" style={{ maxHeight: 400 }}>
          {grouped.length === 0 && (
            <div className="px-3 py-4 text-center text-sm" style={{ color: 'var(--t3)' }}>
              No results
            </div>
          )}
          {grouped.map(({ category, items }) => (
            <div key={category}>
              <div
                className="px-3 py-1 text-xs font-semibold"
                style={{ color: 'var(--t3)', background: 'var(--bg2)' }}
              >
                {CATEGORY_LABELS[category]} ({items.length})
              </div>
              {items.map((entry, i) => (
                <SidebarItemRow
                  key={`${category}-${i}`}
                  name={entry.name}
                  module={entry.context || entry.module.replace('.dll', '')}
                  category={category}
                  active={false}
                  onClick={() => handleSelect(entry)}
                />
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
