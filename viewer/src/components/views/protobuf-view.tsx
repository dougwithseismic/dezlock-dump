import { useSchema } from '../../context/schema-context'
import { CollapsibleSection } from '../shared/collapsible-section'
import { SectionHeader } from '../shared/section-header'

export function ProtobufView() {
  const { D, moduleFilter } = useSchema()

  if (!D) return null

  const pbm = D.protobuf_messages
  if (!pbm || !Object.keys(pbm).length) {
    return <div className="empty">No protobuf messages found</div>
  }

  const mods = Object.keys(pbm).sort()

  return (
    <div>
      <h2 className="cls-name">Protobuf Messages</h2>
      {mods.map((mn) => {
        if (!moduleFilter.has(mn)) return null
        const mod = pbm[mn]
        const files = mod.files || []
        if (!files.length) return null

        let totalMsgs = 0
        files.forEach((f) => {
          totalMsgs += (f.messages || []).length
        })

        return (
          <CollapsibleSection
            key={mn}
            title={mn}
            count={totalMsgs + ' messages, ' + files.length + ' files'}
            defaultOpen={false}
          >
            {[...files]
              .sort((a, b) => a.name.localeCompare(b.name))
              .map((pf) => {
                const msgs = pf.messages || []
                if (!msgs.length) return null

                return (
                  <div key={pf.name}>
                    <SectionHeader
                      title={pf.name + (pf.package ? ' [' + pf.package + ']' : '')}
                      count={msgs.length}
                    />
                    <div className="tw">
                      <table className="ft">
                        <thead>
                          <tr>
                            <th>Message</th>
                            <th>Fields</th>
                            <th>Nested</th>
                          </tr>
                        </thead>
                        <tbody>
                          {[...msgs]
                            .sort((a, b) => a.name.localeCompare(b.name))
                            .map((msg) => {
                              const nested =
                                (msg.nested_messages || []).length + (msg.nested_enums || []).length
                              return (
                                <tr key={msg.name}>
                                  <td>
                                    <a
                                      className="cl"
                                      href={
                                        '#protobuf/' +
                                        encodeURIComponent(mn) +
                                        '/' +
                                        encodeURIComponent(msg.name)
                                      }
                                      onClick={(e) => {
                                        e.preventDefault()
                                        location.hash =
                                          'protobuf/' +
                                          encodeURIComponent(mn) +
                                          '/' +
                                          encodeURIComponent(msg.name)
                                      }}
                                    >
                                      {msg.name}
                                    </a>
                                  </td>
                                  <td>{(msg.fields || []).length}</td>
                                  <td>{nested || '\u2014'}</td>
                                </tr>
                              )
                            })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )
              })}
          </CollapsibleSection>
        )
      })}
    </div>
  )
}
