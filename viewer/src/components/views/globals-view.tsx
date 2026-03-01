import { useSchema } from '../../context/schema-context'
import { useLive } from '../../context/live-context'
import { hs } from '../../lib/format'
import { ClassLink } from '../shared/class-link'
import { CollapsibleSection } from '../shared/collapsible-section'
import { SectionHeader } from '../shared/section-header'

export function GlobalsView() {
  const { D, classMap } = useSchema()
  const { connected } = useLive()

  if (!D) return null

  const globs = D.globals || {}
  const pglobs = D.pattern_globals || {}
  const mods = Object.keys({ ...globs, ...pglobs }).sort()

  if (!mods.length) {
    return <div className="empty">No globals found</div>
  }

  return (
    <div>
      <h2 className="cls-name">Global Singletons</h2>
      {mods.map((mn) => {
        const mg = globs[mn] || []
        const mp = pglobs[mn] || {}
        const pe = Object.entries(mp)
        const total = mg.length + pe.length
        if (!total) return null

        return (
          <CollapsibleSection key={mn} title={mn} count={total} defaultOpen={false}>
            {mg.length > 0 && (
              <div className="tw">
                <table className="ft">
                  <thead>
                    <tr>
                      <th>Class</th>
                      <th>RVA</th>
                      <th>Vtable RVA</th>
                      <th>Type</th>
                      <th>Schema</th>
                      {connected && <th>Address</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {[...mg]
                      .sort((a, b) => a.class.localeCompare(b.class))
                      .map((g, i) => {
                        const ce = classMap.get(g.class)
                        return (
                          <tr key={i}>
                            <td>
                              {ce ? (
                                <ClassLink name={g.class} module={ce.m} />
                              ) : (
                                <a className="cls-link" href={'#global/' + mn + '/' + g.class}>
                                  {g.class}
                                </a>
                              )}
                            </td>
                            <td className="f-off">{hs(g.rva)}</td>
                            <td className="f-off">{hs(g.vtable_rva)}</td>
                            <td>
                              <span
                                className={
                                  'gl-badge' +
                                  (g.type === 'pointer' ? ' gl-badge-p' : '') +
                                  (g.type === 'static' ? ' gl-badge-s' : '')
                                }
                              >
                                {g.type || '?'}
                              </span>
                            </td>
                            <td style={{ color: g.has_schema ? 'var(--ok)' : 'var(--t3)' }}>
                              {g.has_schema ? '\u2713' : '\u2717'}
                            </td>
                            {connected && (
                              <td>
                                {g.rva ? (
                                  <a
                                    className="cl"
                                    href="#"
                                    onClick={(e) => {
                                      e.preventDefault()
                                      const ce2 = classMap.get(g.class)
                                      if (ce2) {
                                        location.hash =
                                          'class/' + encodeURIComponent(ce2.m) + '/' + encodeURIComponent(g.class)
                                      }
                                    }}
                                  >
                                    View Live {'\u2192'}
                                  </a>
                                ) : (
                                  <span className="f-off">{'\u2014'}</span>
                                )}
                              </td>
                            )}
                          </tr>
                        )
                      })}
                  </tbody>
                </table>
              </div>
            )}

            {pe.length > 0 && (
              <>
                <SectionHeader title="Pattern Globals" count={pe.length} />
                <div className="tw">
                  <table className="ft">
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>RVA</th>
                        <th>Mode</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...pe]
                        .sort((a, b) => a[0].localeCompare(b[0]))
                        .map(([pname, pval]) => (
                          <tr key={pname}>
                            <td className="f-name">{pname}</td>
                            <td className="f-off">{hs(pval.rva)}</td>
                            <td className="f-def">{pval.mode || 'riprelative'}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </CollapsibleSection>
        )
      })}
    </div>
  )
}
