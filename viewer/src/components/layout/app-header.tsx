import { useState, useCallback, useRef } from 'react'
import { useSchema } from '../../context/schema-context'
import { useLive } from '../../context/live-context'
import { useTheme } from '../../context/theme-context'
import { createParseWorker } from '../../lib/parse-worker'
import { saveRecentFile, extractFolder } from '../../lib/recent-files'
import type { ParseWorkerMessage } from '../../lib/parse-worker'
import type { SchemaData } from '../../types/schema'
import { fnum } from '../../lib/format'
import { DEFAULT_WS_URL } from '../../lib/constants'

export function AppHeader() {
  const { D, loadData } = useSchema()
  const { connected, latency, connect, disconnect, conLog } = useLive()
  const { toggleTheme } = useTheme()
  const [liveUrl, setLiveUrl] = useState(
    () => localStorage.getItem('live-url') || DEFAULT_WS_URL,
  )
  const fileInputRef = useRef<HTMLInputElement>(null)

  const stats = D
    ? `${fnum(D.total_classes ?? D.modules.reduce((s, m) => s + (m.classes?.length ?? 0), 0))} classes, ${fnum(D.total_fields ?? D.modules.reduce((s, m) => s + (m.classes?.reduce((fs, c) => fs + (c.fields?.length ?? 0), 0) ?? 0), 0))} fields, ${fnum(D.total_enums ?? D.modules.reduce((s, m) => s + (m.enums?.length ?? 0), 0))} enums`
    : ''

  const handleConnect = useCallback(async () => {
    if (connected) {
      disconnect()
    } else {
      const url = liveUrl.trim()
      localStorage.setItem('live-url', url)
      try {
        await connect(url)
      } catch (e) {
        conLog('error', `Connect failed: ${(e as Error).message}`)
      }
    }
  }, [connected, liveUrl, connect, disconnect, conLog])

  const handleFileReload = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (!file) return
      const fileMeta = { name: file.name, size: file.size, lastModified: file.lastModified, folder: extractFolder(file) }
      const reader = new FileReader()
      reader.onload = () => {
        const finish = (data: SchemaData) => {
          saveRecentFile(fileMeta, data).catch(() => {})
          loadData(data)
        }
        try {
          const worker = createParseWorker()
          worker.onmessage = (ev: MessageEvent<ParseWorkerMessage>) => {
            if (ev.data.type === 'done') {
              finish(ev.data.data as SchemaData)
            }
          }
          worker.postMessage({ type: 'parse', text: reader.result })
        } catch {
          try {
            const data = JSON.parse(reader.result as string) as SchemaData
            finish(data)
          } catch {
            /* ignore */
          }
        }
      }
      reader.readAsText(file)
      // Reset so same file can be re-selected
      e.target.value = ''
    },
    [loadData],
  )

  return (
    <header
      className="flex items-center justify-between px-4 shrink-0"
      style={{
        height: 'var(--hdr)',
        background: 'var(--bg1)',
        borderBottom: '1px solid var(--brd)',
      }}
    >
      <div className="flex items-center gap-3">
        <h1
          className="text-base font-bold whitespace-nowrap"
          style={{ color: 'var(--acc)', fontFamily: 'var(--mono)' }}
        >
          dezlock-dump
        </h1>
        {stats && (
          <span className="text-xs hidden sm:inline" style={{ color: 'var(--t3)' }}>
            {stats}
          </span>
        )}
      </div>

      <div className="flex items-center gap-2">
        {/* Live controls */}
        <div className="hidden sm:flex items-center gap-2">
          <span
            className="inline-block w-2 h-2 rounded-full"
            style={{ background: connected ? 'var(--ok)' : 'var(--t3)' }}
          />
          <input
            type="text"
            value={liveUrl}
            onChange={(e) => setLiveUrl(e.target.value)}
            className="px-2 py-1 rounded text-xs"
            style={{
              width: 160,
              background: 'var(--bg0)',
              color: 'var(--t1)',
              border: '1px solid var(--brd)',
              fontFamily: 'var(--mono)',
            }}
          />
          <button
            onClick={handleConnect}
            className="px-3 py-1 rounded text-xs cursor-pointer"
            style={{
              background: 'var(--bg2)',
              color: 'var(--t1)',
              border: '1px solid var(--brd)',
            }}
          >
            {connected ? 'Disconnect' : 'Connect'}
          </button>
          {connected && latency != null && (
            <span className="text-xs" style={{ color: 'var(--t3)' }}>
              {latency}ms
            </span>
          )}
        </div>

        {/* Load JSON */}
        <label
          className="px-3 py-1 rounded text-xs cursor-pointer"
          style={{
            background: 'var(--bg2)',
            color: 'var(--t1)',
            border: '1px solid var(--brd)',
          }}
        >
          Load JSON
          <input
            ref={fileInputRef}
            type="file"
            accept=".json"
            hidden
            onChange={handleFileReload}
          />
        </label>

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="flex items-center justify-center w-8 h-8 rounded cursor-pointer"
          style={{
            background: 'transparent',
            color: 'var(--t2)',
            border: 'none',
          }}
          title="Toggle theme"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" />
          </svg>
        </button>
      </div>
    </header>
  )
}
