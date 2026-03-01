import type { SchemaData } from '../types/schema'

export interface RecentFileEntry {
  /** Unique key: filename + size + lastModified */
  key: string
  name: string
  /** Parent folder path, if available (Electron or webkitRelativePath) */
  folder?: string
  size: number
  lastModified: number
  loadedAt: number
  classCount: number
  enumCount: number
  moduleCount: number
}

const LS_KEY = 'recent-files'
const DB_NAME = 'dezlock-viewer'
const DB_VERSION = 1
const STORE_NAME = 'schema-cache'
const MAX_ENTRIES = 5

// ── localStorage metadata ────────────────────────────────────────

export function getRecentFiles(): RecentFileEntry[] {
  try {
    const raw = localStorage.getItem(LS_KEY)
    return raw ? (JSON.parse(raw) as RecentFileEntry[]) : []
  } catch {
    return []
  }
}

function saveRecentFiles(entries: RecentFileEntry[]) {
  localStorage.setItem(LS_KEY, JSON.stringify(entries.slice(0, MAX_ENTRIES)))
}

export function removeRecentFile(key: string) {
  const entries = getRecentFiles().filter((e) => e.key !== key)
  saveRecentFiles(entries)
  deleteFromIDB(key).catch(() => {})
}

// ── IndexedDB for schema data ────────────────────────────────────

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME)
      }
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function deleteFromIDB(key: string) {
  const db = await openDB()
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    tx.objectStore(STORE_NAME).delete(key)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

export async function loadFromCache(key: string): Promise<SchemaData | null> {
  try {
    const db = await openDB()
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly')
      const req = tx.objectStore(STORE_NAME).get(key)
      req.onsuccess = () => resolve(req.result ?? null)
      req.onerror = () => reject(req.error)
    })
  } catch {
    return null
  }
}

/** Try to extract the parent folder from a File object. */
export function extractFolder(file: File): string | undefined {
  // Electron exposes the full filesystem path
  const elPath = (file as unknown as { path?: string }).path
  if (elPath) {
    const sep = elPath.includes('\\') ? '\\' : '/'
    const idx = elPath.lastIndexOf(sep)
    return idx > 0 ? elPath.substring(0, idx) : undefined
  }
  // webkitRelativePath is set when using directory upload or some drag-and-drop
  const rel = file.webkitRelativePath
  if (rel) {
    const sep = rel.includes('\\') ? '\\' : '/'
    const idx = rel.lastIndexOf(sep)
    return idx > 0 ? rel.substring(0, idx) : undefined
  }
  return undefined
}

export async function saveRecentFile(
  file: { name: string; size: number; lastModified: number; folder?: string },
  data: SchemaData,
) {
  const key = `${file.name}::${file.size}::${file.lastModified}`
  const entry: RecentFileEntry = {
    key,
    name: file.name,
    folder: file.folder,
    size: file.size,
    lastModified: file.lastModified,
    loadedAt: Date.now(),
    classCount: data.total_classes ?? data.modules.reduce((s, m) => s + (m.classes?.length ?? 0), 0),
    enumCount: data.total_enums ?? data.modules.reduce((s, m) => s + (m.enums?.length ?? 0), 0),
    moduleCount: data.modules.length,
  }

  // Update metadata list (move to front, cap at MAX_ENTRIES)
  const entries = getRecentFiles().filter((e) => e.key !== key)
  entries.unshift(entry)
  saveRecentFiles(entries)

  // Evict old IDB entries beyond MAX_ENTRIES
  const evicted = entries.slice(MAX_ENTRIES)
  for (const old of evicted) {
    deleteFromIDB(old.key).catch(() => {})
  }

  // Store schema data in IDB
  try {
    const db = await openDB()
    return new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite')
      tx.objectStore(STORE_NAME).put(data, key)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error)
    })
  } catch {
    // Non-critical — landing page still works, just no cache
  }
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / 1024 / 1024).toFixed(1) + ' MB'
}

export function formatTimeAgo(ts: number): string {
  const diff = Date.now() - ts
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  if (days < 7) return `${days}d ago`
  return new Date(ts).toLocaleDateString()
}
