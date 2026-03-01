import type {
  LiveMessage,
  LivePendingRequest,
  SubscriptionInfo,
  DiffCallback,
  SubscribeResult,
} from '../types/live'

export class LiveClient {
  ws: WebSocket | null = null
  reqId = 0
  pending = new Map<number, LivePendingRequest>()
  onStatusChange: ((connected: boolean) => void) | null = null
  onLatency: ((ms: number) => void) | null = null
  private _pingTimer: ReturnType<typeof setInterval> | null = null
  private _backoff = 1000
  private _subscriptions = new Map<number, SubscriptionInfo>()
  private _diffListeners = new Map<number, DiffCallback>()

  connect(url: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.ws) this.disconnect()
      this.ws = new WebSocket(url)
      this.ws.onopen = () => {
        this._backoff = 1000
        this.onStatusChange?.(true)
        this._startPing()
        resolve()
      }
      this.ws.onerror = () => reject(new Error('WebSocket connection failed'))
      this.ws.onclose = () => {
        this._stopPing()
        this._subscriptions = new Map()
        this.onStatusChange?.(false)
        this.pending.forEach((p) => p.reject(new Error('disconnected')))
        this.pending.clear()
        this.ws = null
      }
      this.ws.onmessage = (e) => {
        try {
          const msg: LiveMessage = JSON.parse(e.data as string)
          if (msg.id !== undefined) {
            const p = this.pending.get(msg.id)
            if (p) {
              this.pending.delete(msg.id)
              if (msg.ok) p.resolve(msg.data)
              else p.reject(new Error((msg.error as string) || 'unknown error'))
            }
            return
          }
          if (msg.cmd) this._handlePush(msg)
        } catch {
          /* ignore parse errors */
        }
      }
    })
  }

  disconnect() {
    this._stopPing()
    this._subscriptions.clear()
    this._diffListeners.clear()
    if (this.ws) {
      this.ws.onclose = null
      this.ws.close()
      this.ws = null
    }
    this.onStatusChange?.(false)
  }

  send(cmd: string, args?: Record<string, unknown>): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== 1) return reject(new Error('not connected'))
      const id = ++this.reqId
      this.pending.set(id, { resolve, reject })
      this.ws.send(JSON.stringify({ id, cmd, args: args || {} }))
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id)
          reject(new Error('timeout'))
        }
      }, 5000)
    })
  }

  get connected(): boolean {
    return !!this.ws && this.ws.readyState === 1
  }

  private _startPing() {
    this._pingTimer = setInterval(async () => {
      if (!this.connected) return
      const t0 = performance.now()
      try {
        await this.send('ping')
        this.onLatency?.(Math.round(performance.now() - t0))
      } catch {
        /* ignore */
      }
    }, 5000)
  }

  private _stopPing() {
    if (this._pingTimer) {
      clearInterval(this._pingTimer)
      this._pingTimer = null
    }
  }

  private _handlePush(msg: LiveMessage) {
    switch (msg.cmd) {
      case 'mem.diff':
        this._handleDiff(msg.data as { sub_id?: number; changes?: Record<string, unknown> })
        break
      case 'live.disconnected':
        this.disconnect()
        break
    }
  }

  private _handleDiff(data: { sub_id?: number; changes?: Record<string, unknown> } | undefined) {
    if (!data?.changes) return
    const subId = data.sub_id
    if (subId === undefined) return

    const listener = this._diffListeners.get(subId)
    if (listener) {
      listener(data.changes)
    }
  }

  async subscribe(
    addr: string,
    module: string,
    className: string,
    intervalMs: number,
    onDiff?: DiffCallback,
  ): Promise<SubscribeResult> {
    const result = (await this.send('mem.subscribe', {
      addr,
      module,
      class: className,
      interval_ms: intervalMs || 100,
    })) as SubscribeResult
    if (result?.sub_id !== undefined) {
      this._subscriptions.set(result.sub_id, { addr, module, className })
      if (onDiff) this._diffListeners.set(result.sub_id, onDiff)
    }
    return result
  }

  async unsubscribe(subId: number) {
    await this.send('mem.unsubscribe', { sub_id: subId })
    this._subscriptions.delete(subId)
    this._diffListeners.delete(subId)
  }

  async unsubscribeAll() {
    const promises: Promise<unknown>[] = []
    this._subscriptions.forEach((_, subId) => {
      promises.push(this.send('mem.unsubscribe', { sub_id: subId }).catch(() => {}))
    })
    await Promise.all(promises)
    this._subscriptions.clear()
    this._diffListeners.clear()
  }

  async fetchSchema(onProgress?: (msg: string) => void): Promise<unknown> {
    const progress = onProgress || (() => {})

    progress('Fetching modules...')
    const modNames = (await this.send('schema.modules')) as string[]

    const result: { modules: unknown[]; globals: Record<string, unknown> } = {
      modules: [],
      globals: {},
    }
    const total = modNames.length
    let done = 0

    const promises = modNames.map(async (mn) => {
      const [classes, enums] = (await Promise.all([
        this.send('schema.classes', { module: mn }),
        this.send('schema.enums', { module: mn }),
      ])) as [{ name: string }[], { name: string }[]]

      const fullClasses = await Promise.all(
        classes.map((c) => this.send('schema.class', { module: mn, name: c.name })),
      )

      const fullEnums = await Promise.all(
        enums.map((e) => this.send('schema.enum', { module: mn, name: e.name })),
      )

      done++
      progress(`Fetching module ${done}/${total}: ${mn}`)

      return {
        name: mn,
        classes: (fullClasses as Record<string, unknown>[]).map((c) => ({
          name: c.name,
          size: c.size,
          parent: c.parent || null,
          inheritance:
            (c.inheritance_chain as string[])?.length ? c.inheritance_chain : c.parent ? [c.name, c.parent] : null,
          fields: ((c.fields as Record<string, unknown>[]) || []).map((f) => ({
            name: f.name,
            type: f.type,
            offset: f.offset,
            size: f.size,
          })),
          static_fields: ((c.static_fields as Record<string, unknown>[]) || []).map((f) => ({
            name: f.name,
            type: f.type,
            offset: f.offset,
            size: f.size,
          })),
          metadata: c.metadata || [],
        })),
        enums: (fullEnums as Record<string, unknown>[]).map((e) => ({
          name: e.name,
          size: e.size,
          values: ((e.values as Record<string, unknown>[]) || []).map((v) => ({
            name: v.name,
            value: v.value,
          })),
        })),
      }
    })

    result.modules = await Promise.all(promises)

    progress('Fetching globals...')
    try {
      const globalsList = (await this.send('global.list')) as Record<string, unknown>[]
      const globsByMod: Record<string, unknown[]> = {}
      globalsList.forEach((g) => {
        const mn = g.module as string
        if (!globsByMod[mn]) globsByMod[mn] = []
        globsByMod[mn].push({
          class: g.class_name,
          rva: g.global_rva,
          vtable_rva: g.vtable_rva,
          type: g.is_pointer ? 'pointer' : 'static',
          has_schema: g.has_schema,
        })
      })
      result.globals = globsByMod
    } catch {
      /* globals optional */
    }

    progress('Done!')
    return result
  }
}
