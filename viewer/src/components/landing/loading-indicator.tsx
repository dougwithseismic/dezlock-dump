interface LoadingIndicatorProps {
  progress: number
  status: string
  visible: boolean
}

export function LoadingIndicator({ progress, status, visible }: LoadingIndicatorProps) {
  if (!visible) return null

  return (
    <div className="flex flex-col items-center gap-2 w-full max-w-sm mx-auto mt-4">
      <div
        className="w-full rounded-full overflow-hidden"
        style={{ height: 6, background: 'var(--bg2)' }}
      >
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${progress}%`, background: 'var(--acc)' }}
        />
      </div>
      <p style={{ color: 'var(--t2)', fontSize: '.85rem' }}>{status}</p>
    </div>
  )
}
