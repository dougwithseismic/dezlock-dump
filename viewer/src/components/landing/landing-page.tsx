import { useState, useCallback, useRef } from 'react'
import { useSchema } from '../../context/schema-context'
import { useLive } from '../../context/live-context'
import { createParseWorker } from '../../lib/parse-worker'
import { saveRecentFile, loadFromCache, extractFolder } from '../../lib/recent-files'
import type { RecentFileEntry } from '../../lib/recent-files'
import type { ParseWorkerMessage } from '../../lib/parse-worker'
import type { SchemaData } from '../../types/schema'
import { DropZone } from './drop-zone'
import { RecentFilesList } from './recent-files-list'
import { LoadingIndicator } from './loading-indicator'
import { DEFAULT_WS_URL } from '../../lib/constants'

export function LandingPage() {
  const { loadData } = useSchema()
  const { client, connect } = useLive()
  const [progress, setProgress] = useState(0)
  const [status, setStatus] = useState('')
  const [loading, setLoading] = useState(false)
  const [liveUrl, setLiveUrl] = useState(
    () => localStorage.getItem('live-url') || DEFAULT_WS_URL,
  )
  const workerRef = useRef<Worker | null>(null)
  const fileMetaRef = useRef<{ name: string; size: number; lastModified: number; folder?: string } | null>(null)

  const handleFile = useCallback(
    (file: File) => {
      fileMetaRef.current = { name: file.name, size: file.size, lastModified: file.lastModified, folder: extractFolder(file) }
      setLoading(true)
      setProgress(0)
      setStatus(`Reading file (${Math.round(file.size / 1024 / 1024)} MB)...`)

      const reader = new FileReader()
      reader.onprogress = (e) => {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 50)
          setProgress(pct)
          setStatus(
            `Reading file... ${Math.round(e.loaded / 1024 / 1024)}/${Math.round(e.total / 1024 / 1024)} MB`,
          )
        }
      }
      reader.onload = () => {
        setProgress(50)
        setStatus('Parsing JSON (this may take a moment)...')
        parseInWorker(reader.result as string)
      }
      reader.onerror = () => {
        setStatus(`Error reading file: ${reader.error}`)
      }
      reader.readAsText(file)
    },
    [loadData],
  )

  const finishLoad = useCallback(
    (data: SchemaData) => {
      // Save to recent files cache (non-blocking)
      if (fileMetaRef.current) {
        saveRecentFile(fileMetaRef.current, data).catch(() => {})
      }
      loadData(data)
    },
    [loadData],
  )

  const parseInWorker = useCallback(
    (text: string) => {
      try {
        const worker = createParseWorker()
        workerRef.current = worker
        worker.onmessage = (e: MessageEvent<ParseWorkerMessage>) => {
          const msg = e.data
          if (msg.type === 'status') {
            setStatus(msg.text || '')
          } else if (msg.type === 'done') {
            setProgress(80)
            setStatus('Building indices...')
            setTimeout(() => finishLoad(msg.data as SchemaData), 0)
          } else if (msg.type === 'error') {
            setStatus(`Parse error: ${msg.message}`)
          }
        }
        worker.postMessage({ type: 'parse', text })
      } catch {
        setStatus('Parsing on main thread...')
        setTimeout(() => {
          try {
            const data = JSON.parse(text) as SchemaData
            const mods = data.modules || []
            for (const m of mods) {
              for (const vt of m.vtables || []) {
                for (const fn of vt.functions || []) {
                  delete (fn as unknown as Record<string, unknown>).bytes
                }
              }
            }
            finishLoad(data)
          } catch (e) {
            setStatus(`Parse error: ${(e as Error).message}`)
          }
        }, 0)
      }
    },
    [finishLoad],
  )

  const handleRecentSelect = useCallback(
    async (entry: RecentFileEntry) => {
      setLoading(true)
      setProgress(30)
      setStatus('Loading from cache...')

      const data = await loadFromCache(entry.key)
      if (data) {
        setProgress(80)
        setStatus('Building indices...')
        fileMetaRef.current = { name: entry.name, size: entry.size, lastModified: entry.lastModified, folder: entry.folder }
        setTimeout(() => finishLoad(data), 0)
      } else {
        setLoading(false)
        setStatus('Cache expired — please re-drop the file.')
      }
    },
    [finishLoad],
  )

  const handleLiveConnect = useCallback(async () => {
    setLoading(true)
    setProgress(0)
    setStatus('Connecting...')
    localStorage.setItem('live-url', liveUrl)

    try {
      await connect(liveUrl)
      setStatus('Fetching schema...')
      const data = await client.fetchSchema((msg) => {
        setStatus(msg)
        setProgress((p) => Math.min(p + 10, 90))
      })
      setProgress(95)
      setStatus('Building indices...')
      setTimeout(() => loadData(data as SchemaData), 0)
    } catch (e) {
      setStatus(`Connect failed: ${(e as Error).message}`)
      setLoading(false)
    }
  }, [liveUrl, connect, client, loadData])

  return (
    <div
      className="flex items-center justify-center h-screen"
      style={{ background: 'var(--bg0)' }}
    >
      <div className="flex flex-col items-center gap-6 max-w-md w-full px-4">
        <h1
          className="text-3xl font-bold"
          style={{ color: 'var(--t1)', fontFamily: 'var(--mono)' }}
        >
          dezlock-dump viewer
        </h1>
        <p style={{ color: 'var(--t2)' }}>Interactive browser for schema dump exports</p>

        {!loading && (
          <>
            <DropZone onFile={handleFile} />

            <RecentFilesList onSelect={handleRecentSelect} />

            <div
              className="flex items-center gap-3 w-full"
              style={{ color: 'var(--t3)' }}
            >
              <div className="flex-1 h-px" style={{ background: 'var(--brd)' }} />
              <span className="text-sm">or</span>
              <div className="flex-1 h-px" style={{ background: 'var(--brd)' }} />
            </div>
            <div className="flex gap-2 w-full">
              <input
                type="text"
                value={liveUrl}
                onChange={(e) => setLiveUrl(e.target.value)}
                placeholder={DEFAULT_WS_URL}
                className="flex-1 px-3 py-2 rounded text-sm"
                style={{
                  background: 'var(--bg1)',
                  color: 'var(--t1)',
                  border: '1px solid var(--brd)',
                  fontFamily: 'var(--mono)',
                }}
              />
              <button
                onClick={handleLiveConnect}
                className="px-4 py-2 rounded text-sm cursor-pointer"
                style={{
                  background: 'var(--bg2)',
                  color: 'var(--t1)',
                  border: '1px solid var(--brd)',
                }}
              >
                Connect Live
              </button>
            </div>
          </>
        )}

        <LoadingIndicator progress={progress} status={status} visible={loading} />
      </div>
    </div>
  )
}
