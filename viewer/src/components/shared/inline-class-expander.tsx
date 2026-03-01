import { useState } from 'react'
import { useSchema } from '../../context/schema-context'
import { h, extractType } from '../../lib/format'
import { ClassLink } from './class-link'
import { CopyFieldButton } from './copy-field-button'
import type { Field } from '../../types/schema'

interface InlineClassExpanderProps {
  className: string
  module: string
  preferModule?: string
  depth?: number
}

const MAX_DEPTH = 3

export function InlineClassExpander({ className, module, preferModule, depth = 1 }: InlineClassExpanderProps) {
  const { classMap, resolveClassMod } = useSchema()
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set())

  const entry = classMap.get(className)
  if (!entry) return <div className="inline-expand-empty">Class "{className}" not found</div>

  const cls = entry.o
  const fields = cls.fields || []

  const toggleRow = (index: number) => {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(index)) next.delete(index)
      else next.add(index)
      return next
    })
  }

  const resolvedMod = module || entry.m

  return (
    <div className="inline-expand-container">
      <div className="inline-expand-header">
        <span className="inline-expand-cls-name">{cls.name}</span>
        <span className="inline-expand-meta">
          {cls.size} bytes ({h(cls.size)}) &middot; {fields.length} fields
        </span>
        <a
          className="inline-expand-fullpage"
          href={location.origin + location.pathname + '#class/' + encodeURIComponent(resolvedMod) + '/' + encodeURIComponent(cls.name)}
          target="_blank"
          rel="noopener noreferrer"
        >
          Go to full page &rsaquo;
        </a>
      </div>
      {fields.length === 0 ? (
        <div className="inline-expand-empty">No fields</div>
      ) : (
        <table className="inline-expand-table">
          <thead>
            <tr>
              <th>Offset</th>
              <th>Name</th>
              <th>Type</th>
              <th>Size</th>
            </tr>
          </thead>
          <tbody>
            {fields.map((f: Field, i: number) => {
              const typeName = extractType(f.type)
              const typeMod = typeName ? resolveClassMod(typeName, preferModule) : null
              const canExpand = depth < MAX_DEPTH && !!typeName && !!typeMod
              const isExpanded = expandedRows.has(i)

              return (
                <ExpandableFieldRow
                  key={i}
                  field={f}
                  index={i}
                  typeName={typeName}
                  typeMod={typeMod}
                  preferModule={preferModule}
                  parentModule={resolvedMod}
                  canExpand={canExpand}
                  isExpanded={isExpanded}
                  onToggle={toggleRow}
                  depth={depth}
                />
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}

interface ExpandableFieldRowProps {
  field: Field
  index: number
  typeName: string | null
  typeMod: string | null
  preferModule?: string
  parentModule: string
  canExpand: boolean
  isExpanded: boolean
  onToggle: (index: number) => void
  depth: number
}

function ExpandableFieldRow({
  field,
  index,
  typeName,
  typeMod,
  preferModule,
  parentModule,
  canExpand,
  isExpanded,
  onToggle,
  depth,
}: ExpandableFieldRowProps) {
  return (
    <>
      <tr>
        <td className="f-off">{h(field.offset)}</td>
        <td className="f-name">
          {field.name}
          <CopyFieldButton text={`[${parentModule}]+${h(field.offset)} ${field.name} // ${field.type || ''}`} />
        </td>
        <td className="f-type">
          {typeName && typeMod ? (
            <>
              {canExpand && (
                <button
                  className="inline-expand-btn"
                  onClick={() => onToggle(index)}
                  title={isExpanded ? 'Collapse' : 'Expand inline'}
                >
                  {isExpanded ? '\u25BC' : '\u25B6'}
                </button>
              )}
              <ClassLink name={typeName} module={typeMod} preferModule={preferModule} />
              {(() => {
                const rest = (field.type || '').replace(typeName, '').trim()
                return rest ? ' ' + rest : ''
              })()}
            </>
          ) : (
            field.type || '\u2014'
          )}
        </td>
        <td className="f-size">{field.size != null ? String(field.size) : '\u2014'}</td>
      </tr>
      {isExpanded && typeName && typeMod && (
        <tr className="inline-expand-row">
          <td colSpan={4}>
            <InlineClassExpander
              className={typeName}
              module={typeMod}
              preferModule={preferModule}
              depth={depth + 1}
            />
          </td>
        </tr>
      )}
    </>
  )
}
