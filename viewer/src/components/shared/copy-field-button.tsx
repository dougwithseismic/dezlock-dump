import { useState, useRef } from 'react'

interface CopyFieldButtonProps {
  text: string
}

export function CopyFieldButton({ text }: CopyFieldButtonProps) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const handleClick = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => setCopied(false), 1200)
  }

  return (
    <span className="row-copy-wrap">
      <button
        className={'row-copy-btn' + (copied ? ' copied' : '')}
        title="Copy field reference"
        onClick={handleClick}
      >
        {copied ? '\u2713' : 'C'}
      </button>
    </span>
  )
}
