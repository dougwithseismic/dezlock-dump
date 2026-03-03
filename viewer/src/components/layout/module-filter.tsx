import { useCallback } from 'react'
import { useSchema } from '../../context/schema-context'

export function ModuleFilter() {
  const { moduleNames, moduleFilter, setModuleFilter } = useSchema()

  const handleToggle = useCallback(
    (mn: string, checked: boolean) => {
      const next = new Set(moduleFilter)
      if (checked) next.add(mn)
      else next.delete(mn)
      setModuleFilter(next)
    },
    [moduleFilter, setModuleFilter],
  )

  const handleAll = useCallback(() => {
    setModuleFilter(new Set(moduleNames))
  }, [moduleNames, setModuleFilter])

  const handleNone = useCallback(() => {
    setModuleFilter(new Set())
  }, [setModuleFilter])

  return (
    <div
      className="px-3 py-2 text-xs overflow-y-auto"
      style={{ borderBottom: '1px solid var(--brd)', maxHeight: 180 }}
    >
      <div className="flex items-center justify-between mb-1">
        <span style={{ color: 'var(--t2)', fontWeight: 600 }}>
          Modules ({moduleNames.length})
        </span>
        <div className="flex gap-1">
          <button
            onClick={handleAll}
            className="px-2 py-0.5 rounded text-xs cursor-pointer"
            style={{
              background: 'var(--bg2)',
              color: 'var(--t2)',
              border: '1px solid var(--brd)',
            }}
          >
            All
          </button>
          <button
            onClick={handleNone}
            className="px-2 py-0.5 rounded text-xs cursor-pointer"
            style={{
              background: 'var(--bg2)',
              color: 'var(--t2)',
              border: '1px solid var(--brd)',
            }}
          >
            None
          </button>
        </div>
      </div>
      {moduleNames.map((mn) => {
        const hasClient = moduleNames.some(m => m.toLowerCase() === 'client.dll')
        const isServer = mn.toLowerCase() === 'server.dll'
        return (
          <label
            key={mn}
            className="flex items-center gap-1.5 py-0.5 cursor-pointer"
            style={{ color: 'var(--t2)' }}
          >
            <input
              type="checkbox"
              checked={moduleFilter.has(mn)}
              onChange={(e) => handleToggle(mn, e.target.checked)}
            />
            <span className="truncate">{mn}</span>
            {hasClient && isServer && (
              <span style={{ color: 'var(--t3)', fontSize: '0.7rem', opacity: 0.7 }}>(mirrors client)</span>
            )}
          </label>
        )
      })}
    </div>
  )
}
