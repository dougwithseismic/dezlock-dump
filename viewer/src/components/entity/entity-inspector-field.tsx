import { useRef, useLayoutEffect } from 'react'
import { useSchema } from '../../context/schema-context'
import { extractType } from '../../lib/format'
import { ClassLink } from '../shared/class-link'
import { LiveValueCell } from '../live-renderers/live-value-cell'

interface EntityInspectorFieldProps {
  name: string
  type: string
  offset: number
  liveValue: unknown
  editorType: string
  module: string
  diffFlash?: boolean
  flashTick?: number
  diffTitle?: string
  enumMap?: Map<string, { o: { items?: { name: string; value: number }[] } }>
  classMap?: Map<string, unknown>
  selectedEntityAddr?: string
  onExpand?: () => void
  isExpanded?: boolean
}

export function EntityInspectorField({
  name,
  type,
  offset,
  liveValue,
  module,
  diffFlash = false,
  flashTick,
  diffTitle,
  enumMap,
  classMap,
  selectedEntityAddr,
  onExpand,
  isExpanded,
}: EntityInspectorFieldProps) {
  const { enumMap: schemaEnumMap, resolveClassMod } = useSchema()
  const valRef = useRef<HTMLDivElement>(null)

  // Force CSS animation restart when flashTick changes while flashing
  useLayoutEffect(() => {
    if (diffFlash && valRef.current) {
      const el = valRef.current
      el.style.animation = 'none'
      void el.offsetHeight
      el.style.animation = ''
    }
  }, [diffFlash, flashTick])

  const typeName = extractType(type)
  const typeModule = typeName ? resolveClassMod(typeName, module) : null
  const typeEnumEntry = typeName ? schemaEnumMap.get(typeName) : null
  const rest = typeName ? (type || '').replace(typeName, '').trim() : ''

  return (
    <div
      className="insp-field"
      data-field-name={name}
      data-field-type={type}
    >
      <div className="insp-field-name">
        <span className="f-off">0x{offset.toString(16).toUpperCase()}</span>
        {name}
        <span className="f-type">
          {' '}
          {typeName && typeModule ? (
            <>
              <ClassLink
                name={typeName}
                module={typeModule}
                preferModule={module}
                onExpand={onExpand}
                isExpanded={isExpanded}
              />
              {rest && ' ' + rest}
            </>
          ) : typeName && typeEnumEntry ? (
            <>
              <a
                className="cl"
                href={
                  '#enum/' +
                  encodeURIComponent(typeEnumEntry.m) +
                  '/' +
                  encodeURIComponent(typeName)
                }
              >
                {typeName}
              </a>
              {rest && ' ' + rest}
            </>
          ) : (
            type || ''
          )}
        </span>
      </div>
      <div
        ref={valRef}
        className={
          'insp-field-val live-val' + (diffFlash ? ' live-diff-flash' : '')
        }
        data-live-field={name}
        data-live-type={type}
        data-field-offset={offset}
        title={diffTitle}
      >
        <LiveValueCell
          fieldType={type}
          value={liveValue}
          enumMap={enumMap}
          classMap={classMap}
          selectedEntityAddr={selectedEntityAddr}
          fieldOffset={offset}
        />
      </div>
    </div>
  )
}
