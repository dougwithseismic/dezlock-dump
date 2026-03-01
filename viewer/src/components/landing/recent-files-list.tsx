import { useState } from 'react'
import {
  getRecentFiles,
  removeRecentFile,
  formatFileSize,
  formatTimeAgo,
} from '../../lib/recent-files'
import type { RecentFileEntry } from '../../lib/recent-files'

interface RecentFilesListProps {
  onSelect: (entry: RecentFileEntry) => void
}

export function RecentFilesList({ onSelect }: RecentFilesListProps) {
  const [entries, setEntries] = useState(getRecentFiles)

  if (entries.length === 0) return null

  const handleRemove = (e: React.MouseEvent, key: string) => {
    e.stopPropagation()
    removeRecentFile(key)
    setEntries(getRecentFiles())
  }

  return (
    <div className="recent-files">
      <div className="recent-files-hdr">Recent</div>
      {entries.map((entry) => (
        <div
          key={entry.key}
          className="recent-file-row"
          onClick={() => onSelect(entry)}
        >
          <div className="recent-file-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
              <polyline points="14 2 14 8 20 8" />
            </svg>
          </div>
          <div className="recent-file-info">
            <div className="recent-file-name">
              {entry.name}
              {entry.folder && (
                <span className="recent-file-folder" title={entry.folder}>
                  {' \u2014 '}
                  {entry.folder}
                </span>
              )}
            </div>
            <div className="recent-file-meta">
              {formatFileSize(entry.size)}
              {' \u00B7 '}
              {entry.moduleCount} modules, {entry.classCount} classes, {entry.enumCount} enums
              {' \u00B7 '}
              {formatTimeAgo(entry.loadedAt)}
            </div>
          </div>
          <button
            className="recent-file-remove"
            title="Remove from recents"
            onClick={(e) => handleRemove(e, entry.key)}
          >
            {'\u2715'}
          </button>
        </div>
      ))}
    </div>
  )
}
