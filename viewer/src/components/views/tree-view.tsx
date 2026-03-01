import { useState, useCallback } from 'react'
import { useSchema } from '../../context/schema-context'

export function TreeView() {
  const { rootClasses, allClasses, classMap, childrenMap } = useSchema()

  return (
    <div>
      <h2 className="cls-name">Inheritance Tree</h2>
      <div className="cls-meta">
        <span className="cm-item">
          <span className="cm-label">Root classes: </span>
          <span>{rootClasses.length}</span>
        </span>
        <span className="cm-item">
          <span className="cm-label">Total classes: </span>
          <span>{allClasses.length}</span>
        </span>
      </div>
      <div className="tree" style={{ marginTop: '16px' }}>
        {rootClasses.map((rn) => (
          <TreeNode key={rn} name={rn} depth={0} classMap={classMap} childrenMap={childrenMap} />
        ))}
      </div>
    </div>
  )
}

interface TreeNodeProps {
  name: string
  depth: number
  classMap: Map<string, { m: string; o: { size: number } }>
  childrenMap: Map<string, string[]>
}

function TreeNode({ name, depth, classMap, childrenMap }: TreeNodeProps) {
  const [expanded, setExpanded] = useState(false)
  const entry = classMap.get(name)
  if (!entry) return null

  const kids = childrenMap.get(name) || []
  const hasKids = kids.length > 0

  const toggle = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation()
      if (hasKids) setExpanded((p) => !p)
    },
    [hasKids],
  )

  const info: string[] = []
  if (entry.o.size) info.push(entry.o.size + 'B')
  if (hasKids) info.push(kids.length + ' children')

  return (
    <div className="tn" style={depth === 0 ? { paddingLeft: 0 } : undefined}>
      <div className="tn-hdr">
        <span
          className={'tn-tog' + (!hasKids ? ' leaf' : '') + (expanded ? ' exp' : '')}
          onClick={toggle}
        >
          {'\u25B6'}
        </span>
        <a
          className="tn-name"
          href={'#class/' + encodeURIComponent(entry.m) + '/' + encodeURIComponent(name)}
          onClick={(e) => {
            e.preventDefault()
            location.hash = 'class/' + encodeURIComponent(entry.m) + '/' + encodeURIComponent(name)
          }}
        >
          {name}
        </a>
        {info.length > 0 && <span className="tn-info">({info.join(', ')})</span>}
      </div>
      {hasKids && (
        <div className={'tn-kids' + (expanded ? ' exp' : '')}>
          {expanded &&
            [...kids]
              .sort()
              .map((cn) => (
                <TreeNode key={cn} name={cn} depth={depth + 1} classMap={classMap} childrenMap={childrenMap} />
              ))}
        </div>
      )}
    </div>
  )
}
