import { useState, useEffect, useRef, useCallback } from 'react'
import { LiveClient } from '../lib/live-client'

export function useLiveClient() {
  const clientRef = useRef<LiveClient | null>(null)
  const [connected, setConnected] = useState(false)
  const [latency, setLatency] = useState<number | null>(null)

  if (!clientRef.current) {
    clientRef.current = new LiveClient()
  }

  useEffect(() => {
    const client = clientRef.current!
    client.onStatusChange = (c) => {
      setConnected(c)
      if (!c) setLatency(null)
    }
    client.onLatency = (ms) => setLatency(ms)
    return () => {
      client.onStatusChange = null
      client.onLatency = null
    }
  }, [])

  const connect = useCallback(async (url: string) => {
    await clientRef.current!.connect(url)
  }, [])

  const disconnect = useCallback(() => {
    clientRef.current!.disconnect()
  }, [])

  return {
    client: clientRef.current,
    connected,
    latency,
    connect,
    disconnect,
  }
}
