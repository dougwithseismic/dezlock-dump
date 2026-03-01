import { createContext, useContext, useCallback, useMemo, type ReactNode } from 'react'
import { useLiveClient } from '../hooks/use-live-client'
import type { LiveClient } from '../lib/live-client'

interface LiveContextValue {
  client: LiveClient
  connected: boolean
  latency: number | null
  connect: (url: string) => Promise<void>
  disconnect: () => void
  conLog: (type: string, text: string) => void
}

const LiveContext = createContext<LiveContextValue>(null!)

export function LiveProvider({ children }: { children: ReactNode }) {
  const { client, connected, latency, connect, disconnect } = useLiveClient()

  const conLog = useCallback((_type: string, _text: string) => {
    // Console logging is handled locally by ConsoleDrawer
  }, [])

  const value = useMemo<LiveContextValue>(
    () => ({
      client: client!,
      connected,
      latency,
      connect,
      disconnect,
      conLog,
    }),
    [client, connected, latency, connect, disconnect, conLog],
  )

  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>
}

export function useLive() {
  return useContext(LiveContext)
}
