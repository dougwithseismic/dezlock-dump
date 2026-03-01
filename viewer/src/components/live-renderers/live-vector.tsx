interface LiveVectorProps {
  value: number[]
}

const LABELS = ['x', 'y', 'z', 'w']

export function LiveVector({ value }: LiveVectorProps) {
  return (
    <>
      {value.map((v, i) => (
        <span key={i}>
          {i > 0 && ' '}
          <span className="live-vec-label">{LABELS[i] || String(i)}</span>
          <span className="live-vec-comp" title="Drag to scrub, double-click to edit">
            {typeof v === 'number' ? v.toFixed(2) : String(v)}
          </span>
        </span>
      ))}
    </>
  )
}
