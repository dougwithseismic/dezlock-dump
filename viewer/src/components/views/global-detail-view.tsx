import { useSchema } from '../../context/schema-context'
import { hs } from '../../lib/format'
import { ClassLink } from '../shared/class-link'
import { SectionHeader } from '../shared/section-header'

interface GlobalDetailViewProps {
  name: string
  module: string
}

export function GlobalDetailView({ name, module }: GlobalDetailViewProps) {
  const { D, classMap } = useSchema()

  if (!D) return null

  const globs = (D.globals || {})[module] || []
  const g = globs.find((x) => x.class === name)

  if (!g) {
    return (
      <div className="empty">
        Global "{name}" not found in {module}
      </div>
    )
  }

  const ce = classMap.get(name)

  return (
    <div>
      <h2 className="cls-name">{name}</h2>
      <div className="cls-meta">
        <span className="cm-item">
          <span className="cm-label">Module: </span>
          <span>{module.replace('.dll', '')}</span>
        </span>
        <span className="cm-item">
          <span className="cm-label">Type: </span>
          <span
            className={
              'gl-badge' +
              (g.type === 'pointer' ? ' gl-badge-p' : '') +
              (g.type === 'static' ? ' gl-badge-s' : '')
            }
          >
            {g.type || '?'}
          </span>
        </span>
        {g.has_schema ? (
          <span className="cm-item">
            <span className="cm-label">Schema: </span>
            <a
              className="cls-link"
              href={'#class/' + (ce ? ce.m : module) + '/' + name}
            >
              View Schema Class {'\u2192'}
            </a>
          </span>
        ) : (
          <span className="cm-item">
            <span className="cm-label">Schema: </span>
            <span>No</span>
          </span>
        )}
      </div>

      <div className="tw">
        <table className="ft">
          <thead>
            <tr>
              <th>Property</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="f-name">RVA</td>
              <td className="f-off">{hs(g.rva)}</td>
            </tr>
            <tr>
              <td className="f-name">Vtable RVA</td>
              <td className="f-off">{hs(g.vtable_rva)}</td>
            </tr>
            {g.function_count !== undefined && (
              <tr>
                <td className="f-name">Vtable Functions</td>
                <td className="f-off">{String(g.function_count)}</td>
              </tr>
            )}
            {g.parent && (
              <tr>
                <td className="f-name">Parent</td>
                <td className="f-off">{g.parent}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {g.inheritance && g.inheritance.length > 0 && (
        <>
          <SectionHeader title="Inheritance Chain" count={g.inheritance.length} />
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              alignItems: 'center',
              gap: '4px',
              marginTop: '8px',
            }}
          >
            {g.inheritance.map((cn, i) => {
              const ce2 = classMap.get(cn)
              return (
                <span key={i}>
                  {i > 0 && <span>{'\u2192'} </span>}
                  {ce2 ? <ClassLink name={cn} module={ce2.m} /> : <span>{cn}</span>}
                </span>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}
