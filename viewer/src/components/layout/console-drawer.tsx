import { useState, useCallback, useRef, useEffect } from 'react'
import { useLive } from '../../context/live-context'

interface ConsoleDrawerProps {
  open: boolean
  onToggle: () => void
}

interface ConsoleLine {
  type: string
  text: string
  time: number
}

export function ConsoleDrawer({ open, onToggle }: ConsoleDrawerProps) {
  const { client, connected, conLog } = useLive()
  const [height, setHeight] = useState(200)
  const [lines, setLines] = useState<ConsoleLine[]>([])
  const [cmdValue, setCmdValue] = useState('')
  const bodyRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const dragState = useRef<{ dragging: boolean; startY: number; startH: number }>({
    dragging: false,
    startY: 0,
    startH: 0,
  })

  const addLine = useCallback((type: string, text: string) => {
    setLines((prev) => [...prev.slice(-199), { type, text, time: Date.now() }])
  }, [])

  useEffect(() => {
    if (open && inputRef.current) inputRef.current.focus()
  }, [open])

  useEffect(() => {
    if (bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight
    }
  }, [lines])

  // Drag resize
  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault()
      dragState.current = { dragging: true, startY: e.clientY, startH: height }
      const onMove = (ev: MouseEvent) => {
        if (!dragState.current.dragging) return
        let newH = dragState.current.startH + (dragState.current.startY - ev.clientY)
        if (newH < 80) newH = 80
        if (newH > window.innerHeight * 0.6) newH = Math.floor(window.innerHeight * 0.6)
        setHeight(newH)
      }
      const onUp = () => {
        dragState.current.dragging = false
        document.removeEventListener('mousemove', onMove)
        document.removeEventListener('mouseup', onUp)
      }
      document.addEventListener('mousemove', onMove)
      document.addEventListener('mouseup', onUp)
    },
    [height],
  )

  const parseArgs = useCallback((cmd: string, argsStr: string): Record<string, unknown> => {
    if (!argsStr) return {}

    // Try JSON parse first
    try {
      return JSON.parse(argsStr)
    } catch {
      // noop
    }

    // Try key=value pairs
    const kvPairs = argsStr.match(/(\w+)=("[^"]*"|'[^']*'|\S+)/g)
    if (kvPairs) {
      const args: Record<string, unknown> = {}
      kvPairs.forEach((kv) => {
        const eq = kv.indexOf('=')
        const k = kv.substring(0, eq)
        const v = kv.substring(eq + 1).replace(/^["']|["']$/g, '')
        if (!isNaN(Number(v)) && v !== '') args[k] = Number(v)
        else if (v === 'true') args[k] = true
        else if (v === 'false') args[k] = false
        else args[k] = v
      })
      return args
    }

    // Single positional arg
    if (cmd === 'schema.search') return { query: argsStr }
    if (cmd === 'mem.read') {
      const readParts = argsStr.split(/\s+/)
      return { addr: readParts[0], size: parseInt(readParts[1]) || 64 }
    }
    if (cmd === 'schema.class' || cmd === 'schema.enum') {
      const dotParts = argsStr.split(/[:.]+/)
      if (dotParts.length >= 2) return { module: dotParts[0], name: dotParts.slice(1).join('::') }
      return { name: argsStr }
    }
    return { query: argsStr }
  }, [])

  const sendCmd = useCallback(async () => {
    const raw = cmdValue.trim()
    if (!raw) return
    setCmdValue('')
    addLine('req', '\u2192 ' + raw)
    conLog('req', '\u2192 ' + raw)

    if (!connected) {
      addLine('error', 'Not connected')
      return
    }

    const parts = raw.split(/\s+/)
    const cmd = parts[0]
    const argsStr = parts.slice(1).join(' ')
    const args = parseArgs(cmd, argsStr)

    try {
      const result = await client.send(cmd, args)
      let resultStr = JSON.stringify(result, null, 2)
      if (resultStr.length > 500) resultStr = resultStr.substring(0, 500) + '... (truncated)'
      addLine('res', '\u2190 ' + resultStr)
      conLog('res', '\u2190 ' + resultStr)
    } catch (e) {
      addLine('error', (e as Error).message)
      conLog('error', (e as Error).message)
    }
  }, [cmdValue, connected, client, addLine, conLog, parseArgs])

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') {
        e.preventDefault()
        sendCmd()
      }
    },
    [sendCmd],
  )

  if (!open) return null

  const lineColor = (type: string) => {
    switch (type) {
      case 'req': return 'var(--t3)'
      case 'res': return 'var(--ok)'
      case 'error': return '#f85149'
      case 'info': return 'var(--t2)'
      default: return 'var(--t1)'
    }
  }

  return (
    <div
      className="relative flex flex-col shrink-0 overflow-hidden"
      style={{
        height,
        borderTop: '1px solid var(--brd)',
        background: 'var(--bg1)',
      }}
    >
      {/* Resize handle */}
      <div
        className="h-1 cursor-ns-resize shrink-0 hover:opacity-100"
        style={{ background: 'transparent' }}
        onMouseDown={handleMouseDown}
        onMouseEnter={(e) => {
          ;(e.currentTarget as HTMLElement).style.background = 'var(--acc-d)'
        }}
        onMouseLeave={(e) => {
          ;(e.currentTarget as HTMLElement).style.background = 'transparent'
        }}
      />

      {/* Header */}
      <div
        className="flex items-center justify-between px-3 py-1 text-xs cursor-pointer select-none shrink-0"
        style={{ color: 'var(--t2)', background: 'var(--bg2)' }}
        onClick={onToggle}
      >
        <span>Console</span>
        <span>{connected ? 'Connected' : 'Connect to enable'}</span>
      </div>

      {/* Body */}
      <div
        ref={bodyRef}
        className="flex-1 overflow-y-auto px-3 py-1"
        style={{
          fontFamily: 'var(--mono)',
          fontSize: '.78rem',
          minHeight: 0,
        }}
      >
        {lines.map((line, i) => (
          <div
            key={i}
            className="mb-0.5"
            style={{ color: lineColor(line.type), wordBreak: 'break-all' }}
          >
            [{new Date(line.time).toLocaleTimeString()}] {line.text}
          </div>
        ))}
      </div>

      {/* Input */}
      <div
        className="flex gap-1 px-2 py-1 shrink-0"
        style={{ borderTop: '1px solid var(--brd-l)' }}
      >
        <input
          ref={inputRef}
          type="text"
          value={cmdValue}
          onChange={(e) => setCmdValue(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={!connected}
          placeholder={connected ? 'Type a command...' : 'Connect to send commands'}
          className="flex-1 px-2 py-1 rounded text-xs"
          style={{
            fontFamily: 'var(--mono)',
            background: 'var(--bg0)',
            color: 'var(--t1)',
            border: '1px solid var(--brd)',
          }}
        />
        <button
          onClick={sendCmd}
          disabled={!connected}
          className="px-3 py-1 rounded text-xs cursor-pointer"
          style={{
            background: 'var(--bg2)',
            color: connected ? 'var(--t1)' : 'var(--t3)',
            border: '1px solid var(--brd)',
            opacity: connected ? 1 : 0.5,
          }}
        >
          Send
        </button>
      </div>
    </div>
  )
}
