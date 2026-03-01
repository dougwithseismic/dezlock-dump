interface LiveColorProps {
  value: number[]
}

export function LiveColor({ value }: LiveColorProps) {
  const r = value[0] || 0
  const g = value[1] || 0
  const b = value[2] || 0
  const a = value[3] !== undefined ? value[3] : 255

  return (
    <>
      <span
        className="live-swatch"
        style={{ background: `rgba(${r},${g},${b},${(a / 255).toFixed(2)})` }}
      />
      <span className="live-color-text">
        {r}, {g}, {b}, {a}
      </span>
    </>
  )
}
