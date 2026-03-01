interface LiveFloatProps {
  value: number
}

export function LiveFloat({ value }: LiveFloatProps) {
  return (
    <span className="live-num-drag" title="Drag to scrub, double-click to edit">
      {typeof value === 'number' ? value.toFixed(4) : String(value)}
    </span>
  )
}
