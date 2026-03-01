import { useSchema } from '../../context/schema-context'

interface ClassLinkProps {
  name: string
  module?: string
  preferModule?: string
  showCrossModuleBadge?: boolean
  onExpand?: () => void
  isExpanded?: boolean
}

export function ClassLink({ name, module, preferModule, showCrossModuleBadge, onExpand, isExpanded }: ClassLinkProps) {
  const { resolveClassMod } = useSchema()
  const resolved = module || resolveClassMod(name, preferModule)

  if (!resolved) return <span>{name}</span>

  const href = '#class/' + encodeURIComponent(resolved) + '/' + encodeURIComponent(name)
  const showBadge = showCrossModuleBadge && preferModule && resolved !== preferModule

  return (
    <>
      {onExpand && (
        <button
          className="inline-expand-btn"
          onClick={(e) => {
            e.stopPropagation()
            onExpand()
          }}
          title={isExpanded ? 'Collapse' : 'Expand inline'}
        >
          {isExpanded ? '\u25BC' : '\u25B6'}
        </button>
      )}
      <a
        className="cls-link"
        href={href}
        onClick={(e) => {
          e.preventDefault()
          location.hash = 'class/' + encodeURIComponent(resolved) + '/' + encodeURIComponent(name)
        }}
      >
        {name}
      </a>
      {showBadge && (
        <>
          {' '}
          <span className="badge badge-xmod" title={'Type registered in ' + resolved + ' (canonical server name)'}>
            {resolved}
          </span>
        </>
      )}
    </>
  )
}
