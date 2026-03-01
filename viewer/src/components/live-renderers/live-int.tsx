interface LiveIntProps {
  value: number
}

export function LiveInt({ value }: LiveIntProps) {
  return (
    <span className="live-num-drag" title="Drag to scrub, double-click to edit">
      {String(value)}
    </span>
  )
}
