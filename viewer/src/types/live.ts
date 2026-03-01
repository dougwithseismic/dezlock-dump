export interface LiveMessage {
  id?: number
  cmd?: string
  ok?: boolean
  data?: unknown
  error?: string
  args?: Record<string, unknown>
}

export interface LivePendingRequest {
  resolve: (data: unknown) => void
  reject: (error: Error) => void
}

export interface SubscriptionInfo {
  addr: string
  module: string
  className: string
}

export type DiffChanges = Record<string, {
  new?: unknown
  old?: unknown
} | unknown>

export type DiffCallback = (changes: DiffChanges) => void

export interface SubscribeResult {
  sub_id?: number
}

export interface LivePushMessage {
  cmd: string
  data?: {
    sub_id?: number
    changes?: DiffChanges
  }
}
