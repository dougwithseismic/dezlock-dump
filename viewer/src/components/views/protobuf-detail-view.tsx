import { useSchema } from '../../context/schema-context'
import { SectionHeader } from '../shared/section-header'

interface ProtobufDetailViewProps {
  name: string
}

export function ProtobufDetailView({ name }: ProtobufDetailViewProps) {
  const { protoMap } = useSchema()
  const entry = protoMap.get(name)

  if (!entry) {
    return <div className="empty">Protobuf message "{name}" not found</div>
  }

  const msg = entry.o
  const mod = entry.m
  const file = entry.f
  const fields = msg.fields || []
  const oneofs = msg.oneof_decls || []
  const nenums = msg.nested_enums || []
  const nmsgs = msg.nested_messages || []

  return (
    <div>
      <h2 className="cls-name">{msg.name}</h2>
      <div className="cls-meta">
        <span className="cm-item">
          <span className="cm-label">Module: </span>
          <span>{mod}</span>
        </span>
        <span className="cm-item">
          <span className="cm-label">File: </span>
          <span>{file}</span>
        </span>
        <span className="cm-item">
          <span className="cm-label">Fields: </span>
          <span>{fields.length}</span>
        </span>
      </div>

      {fields.length > 0 && (
        <div className="tw">
          <table className="ft">
            <thead>
              <tr>
                <th>#</th>
                <th>Name</th>
                <th>Type</th>
                <th>Label</th>
              </tr>
            </thead>
            <tbody>
              {[...fields]
                .sort((a, b) => a.number - b.number)
                .map((f, i) => {
                  const tname = (f.type_name || '').replace(/^\./, '')
                  const pb = tname ? protoMap.get(tname) : null

                  return (
                    <tr key={i}>
                      <td className="f-off">{f.number}</td>
                      <td className="f-name">
                        {f.name}
                        {f.oneof_index != null && oneofs[f.oneof_index] && (
                          <span className="pb-oneof"> [oneof: {oneofs[f.oneof_index]}]</span>
                        )}
                      </td>
                      <td>
                        {(f.type === 'message' || f.type === 'enum') && pb ? (
                          <a
                            className="cl"
                            href={
                              '#protobuf/' +
                              encodeURIComponent(pb.m) +
                              '/' +
                              encodeURIComponent(tname)
                            }
                            onClick={(e) => {
                              e.preventDefault()
                              location.hash =
                                'protobuf/' +
                                encodeURIComponent(pb.m) +
                                '/' +
                                encodeURIComponent(tname)
                            }}
                          >
                            {tname}
                          </a>
                        ) : (
                          tname || f.type
                        )}
                      </td>
                      <td>
                        <span
                          className={
                            'pb-label' +
                            (f.label === 'repeated' ? ' pb-repeated' : '') +
                            (f.label === 'required' ? ' pb-required' : '')
                          }
                        >
                          {f.label || ''}
                        </span>
                      </td>
                    </tr>
                  )
                })}
            </tbody>
          </table>
        </div>
      )}

      {nenums.length > 0 && (
        <>
          <SectionHeader title="Nested Enums" count={nenums.length} />
          {nenums.map((ne, ni) => (
            <div key={ni} className="tw" style={{ marginBottom: '12px' }}>
              <div className="sec-title" style={{ marginBottom: '4px' }}>
                {ne.name}
              </div>
              <table className="ft">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {(ne.values || []).map((v, vi) => (
                    <tr key={vi}>
                      <td className="f-name">{v.name}</td>
                      <td className="f-off">{v.number}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </>
      )}

      {nmsgs.length > 0 && (
        <>
          <SectionHeader title="Nested Messages" count={nmsgs.length} />
          {nmsgs.map((nm, nmi) => {
            const nfields = nm.fields || []
            return (
              <div key={nmi} style={{ marginLeft: '16px', marginBottom: '16px' }}>
                <h3 className="sec-title">{nm.name}</h3>
                {nfields.length > 0 && (
                  <div className="tw">
                    <table className="ft">
                      <thead>
                        <tr>
                          <th>#</th>
                          <th>Name</th>
                          <th>Type</th>
                          <th>Label</th>
                        </tr>
                      </thead>
                      <tbody>
                        {[...nfields]
                          .sort((a, b) => a.number - b.number)
                          .map((f, fi) => (
                            <tr key={fi}>
                              <td className="f-off">{f.number}</td>
                              <td className="f-name">{f.name}</td>
                              <td>{f.type_name ? f.type_name.replace(/^\./, '') : f.type}</td>
                              <td>{f.label || ''}</td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )
          })}
        </>
      )}
    </div>
  )
}
