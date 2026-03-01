import { useState, useMemo, type ReactNode } from 'react'

export interface DataColumn<T> {
  key: string
  label: string
  render?: (row: T) => ReactNode
}

interface DataTableProps<T> {
  columns: DataColumn<T>[]
  data: T[]
  sortable?: boolean
  defaultSortKey?: string
  defaultSortDir?: 'asc' | 'desc'
}

export function DataTable<T extends Record<string, unknown>>({
  columns,
  data,
  sortable = true,
  defaultSortKey,
  defaultSortDir = 'asc',
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState(defaultSortKey || columns[0]?.key || '')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>(defaultSortDir)

  const sorted = useMemo(() => {
    if (!sortable || !sortKey) return data
    return [...data].sort((a, b) => {
      let va = a[sortKey] as unknown
      let vb = b[sortKey] as unknown
      if (typeof va === 'string') va = va.toLowerCase()
      if (typeof vb === 'string') vb = vb.toLowerCase()
      if ((va as string | number) < (vb as string | number)) return sortDir === 'asc' ? -1 : 1
      if ((va as string | number) > (vb as string | number)) return sortDir === 'asc' ? 1 : -1
      return 0
    })
  }, [data, sortKey, sortDir, sortable])

  const handleSort = (key: string) => {
    if (!sortable) return
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  return (
    <div className="tw">
      <table className="ft">
        <thead>
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                className={sortable && sortKey === col.key ? (sortDir === 'asc' ? 's-asc' : 's-desc') : ''}
                onClick={() => handleSort(col.key)}
                style={sortable ? { cursor: 'pointer' } : undefined}
              >
                {col.label}
                {sortable && sortKey === col.key && (sortDir === 'asc' ? ' \u25B2' : ' \u25BC')}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, i) => (
            <tr key={i}>
              {columns.map((col) => (
                <td key={col.key}>{col.render ? col.render(row) : String(row[col.key] ?? '\u2014')}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
