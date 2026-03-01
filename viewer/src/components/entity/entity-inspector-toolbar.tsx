interface EntityInspectorToolbarProps {
  fieldFilter: string
  onFieldFilterChange: (v: string) => void
  showChanged: boolean
  onShowChangedChange: (v: boolean) => void
  onSnapshot: () => void
  onClearSnapshot: () => void
  snapshotActive: boolean
}

export function EntityInspectorToolbar({
  fieldFilter,
  onFieldFilterChange,
  showChanged,
  onShowChangedChange,
  onSnapshot,
  onClearSnapshot,
  snapshotActive,
}: EntityInspectorToolbarProps) {
  return (
    <div className="insp-toolbar">
      <input
        type="text"
        placeholder="Filter fields..."
        value={fieldFilter}
        onInput={(e) => onFieldFilterChange((e.target as HTMLInputElement).value)}
      />
      <label>
        <input
          type="checkbox"
          checked={showChanged}
          onChange={(e) => onShowChangedChange(e.target.checked)}
        />
        {' Changed'}
      </label>
      <button className="btn btn--s" title="Take snapshot - diff from this point" onClick={onSnapshot}>
        {'\uD83D\uDCF7'}
      </button>
      <button className="btn btn--s" title="Clear snapshot" onClick={onClearSnapshot}>
        {'\u2715'}
      </button>
      <span className="insp-snapshot-badge">{snapshotActive ? 'Snapshot active' : ''}</span>
    </div>
  )
}
