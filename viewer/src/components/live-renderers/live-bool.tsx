interface LiveBoolProps {
  value: unknown
}

export function LiveBool({ value }: LiveBoolProps) {
  return <input type="checkbox" className="live-bool" checked={!!value} disabled />
}
