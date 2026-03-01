import { useState } from 'react'
import { useSchema } from '../../context/schema-context'
import { h, extractType } from '../../lib/format'
import { ClassLink } from './class-link'
import { CopyFieldButton } from './copy-field-button'
import { LiveValueCell } from '../live-renderers/live-value-cell'
import type { Field } from '../../types/schema'

interface InlineClassExpanderProps {
  className: string
  module: string
  preferModule?: string
  depth?: number
  copyPrefix: string
  liveValues?: Record<string, unknown>
  enumMap?: Map<string, { o: { items?: { name: string; value: number }[] } }>
  classMap?: Map<string, unknown>
  selectedEntityAddr?: string
}

const MAX_DEPTH = 3

function extractNestedLiveValues(
  liveValues: Record<string, unknown> | undefined,
  fieldName: string,
): Record<string, unknown> | undefined {
  if (!liveValues) return undefined
  const val = liveValues[fieldName]
  if (val && typeof val === 'object' && '_t' in (val as Record<string, unknown>)) {
    const sv = val as { _t: string; fields?: Record<string, unknown> }
    if (sv._t === 'struct' && sv.fields) return sv.fields
  }
  return undefined
}

export function InlineClassExpander({
  className,
  module,
  preferModule,
  depth = 1,
  copyPrefix,
  liveValues,
  enumMap,
  classMap,
  selectedEntityAddr,
}: InlineClassExpanderProps) {
  const { classMap: schemaClassMap, resolveClassMod } = useSchema()
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set())

  const entry = schemaClassMap.get(className)
  if (!entry) return <div className="inline-expand-empty">Class "{className}" not found</div>

  const cls = entry.o
  const fields = cls.fields || []
  const hasLive = !!liveValues

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
              {hasLive && <th>Live</th>}
            </tr>
          </thead>
          <tbody>
            {fields.map((f: Field, i: number) => {
              const typeName = extractType(f.type)
              const typeMod = typeName ? resolveClassMod(typeName, preferModule) : null
              const canExpand = depth < MAX_DEPTH && !!typeName && !!typeMod
              const isExpanded = expandedRows.has(i)
              const fieldCopyPrefix = `${copyPrefix} -> ${h(f.offset)} ${f.name}`

              return (
                <ExpandableFieldRow
                  key={i}
                  field={f}
                  index={i}
                  typeName={typeName}
                  typeMod={typeMod}
                  preferModule={preferModule}
                  canExpand={canExpand}
                  isExpanded={isExpanded}
                  onToggle={toggleRow}
                  depth={depth}
                  copyPrefix={fieldCopyPrefix}
                  hasLive={hasLive}
                  liveValue={liveValues?.[f.name] ?? null}
                  liveValues={liveValues}
                  enumMap={enumMap}
                  classMap={classMap}
                  selectedEntityAddr={selectedEntityAddr}
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
  canExpand: boolean
  isExpanded: boolean
  onToggle: (index: number) => void
  depth: number
  copyPrefix: string
  hasLive: boolean
  liveValue: unknown
  liveValues?: Record<string, unknown>
  enumMap?: Map<string, { o: { items?: { name: string; value: number }[] } }>
  classMap?: Map<string, unknown>
  selectedEntityAddr?: string
}

function ExpandableFieldRow({
  field,
  index,
  typeName,
  typeMod,
  preferModule,
  canExpand,
  isExpanded,
  onToggle,
  depth,
  copyPrefix,
  hasLive,
  liveValue,
  liveValues,
  enumMap,
  classMap,
  selectedEntityAddr,
}: ExpandableFieldRowProps) {
  const colCount = hasLive ? 5 : 4

  return (
    <>
      <tr>
        <td className="f-off">{h(field.offset)}</td>
        <td className="f-name">
          {field.name}
          <CopyFieldButton text={`${copyPrefix} // ${field.type || ''}`} />
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
        {hasLive && (
          <td className="f-live live-val">
            <LiveValueCell
              fieldType={field.type || ''}
              value={liveValue}
              enumMap={enumMap}
              classMap={classMap}
              selectedEntityAddr={selectedEntityAddr}
              fieldOffset={field.offset}
            />
          </td>
        )}
      </tr>
      {isExpanded && typeName && typeMod && (
        <tr className="inline-expand-row">
          <td colSpan={colCount}>
            <InlineClassExpander
              className={typeName}
              module={typeMod}
              preferModule={preferModule}
              depth={depth + 1}
              copyPrefix={copyPrefix}
              liveValues={extractNestedLiveValues(liveValues, field.name)}
              enumMap={enumMap}
              classMap={classMap}
              selectedEntityAddr={selectedEntityAddr}
            />
          </td>
        </tr>
      )}
    </>
  )
}
