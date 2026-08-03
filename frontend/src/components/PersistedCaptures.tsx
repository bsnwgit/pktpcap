import { useEffect, useState } from 'react'
import { Capture } from '../api/client'
import { fmtBytes } from '../lib/pcap'
import Pagination from './Pagination'
import Spinner from './Spinner'

const STATUS_STYLES: Record<string, string> = {
  saved: 'bg-green-900/40 text-green-400 border border-green-700/40',
  saving: 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/40',
  failed: 'bg-red-900/40 text-red-400 border border-red-700/40',
  missing: 'bg-gray-800 text-gray-400 border border-gray-700',
}

// Same page-size convention as pktflow's Flow Explorer / this app's own
// Logs page — 25/50/75/100, default 25. Pagination is client-side here
// (the full capture list is already fetched in one shot), unlike those
// pages' server-side paging, but the page-number bar + per-page selector
// + "Showing X–Y of Z" footer are the same shared UI pattern.
const PAGE_SIZE_DEFAULT = 25
const PAGE_SIZE_OPTIONS = [25, 50, 75, 100]

function fmtTs(ts: string): string {
  try {
    const d = new Date(ts.includes('T') || ts.endsWith('Z') ? ts : ts.replace(' ', 'T') + 'Z')
    return d.toLocaleString()
  } catch {
    return ts
  }
}

// Shared between the Live Feeds and Upload pages — both persist captures
// into the same server-side list (see app/api/captures.py), just from
// different sources (tshark/Wireshark vs drag-and-drop upload), so the
// table, ownership display, sharing controls, and pagination only need to
// exist once.
export default function PersistedCaptures({
  title, captures, loading, storageConfigured, currentUserId, isAdmin,
  onAnalyze, onDownload, onDelete, onToggleShared,
}: {
  title: string
  captures: Capture[]
  loading: boolean
  storageConfigured: boolean
  currentUserId: number
  isAdmin: boolean
  onAnalyze: (filename: string) => void
  onDownload: (filename: string) => void
  onDelete: (filename: string) => void
  onToggleShared: (filename: string, shared: boolean) => void
}) {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(PAGE_SIZE_DEFAULT)

  const totalPages = Math.max(1, Math.ceil(captures.length / pageSize))
  // Clamp instead of reset-to-1 on every list refresh — a delete/share
  // toggle re-fetches the same list and shouldn't bounce the user back to
  // page 1 unless their current page no longer exists (e.g. they deleted
  // the last item on the last page).
  useEffect(() => { setPage(p => Math.min(p, totalPages)) }, [totalPages])

  const pageCaptures = captures.slice((page - 1) * pageSize, page * pageSize)

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between flex-wrap gap-3">
        <h2 className="text-sm font-semibold text-white">{title}</h2>
        {!storageConfigured && (
          <span className="text-xs text-yellow-400">No storage path configured — captures aren't saved to disk. Set one in Settings → Captures.</span>
        )}
        {captures.length > 0 && (
          <div className="flex items-center gap-4">
            <Pagination page={page} totalPages={totalPages} onChange={setPage} />
            <div className="flex items-center gap-2">
              <label htmlFor={`${title}-per-page`} className="text-xs text-gray-400">Per page:</label>
              <select
                id={`${title}-per-page`}
                value={pageSize}
                onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}
                className="text-sm bg-gray-800 border border-gray-700 text-white rounded-lg px-2 py-1 focus:outline-none focus:border-sky-500"
              >
                {PAGE_SIZE_OPTIONS.map(size => (
                  <option key={size} value={size}>{size}</option>
                ))}
              </select>
            </div>
          </div>
        )}
      </div>
      {captures.length === 0 ? (
        <div className="px-6 py-8 text-center text-sm text-gray-500">
          {loading ? <Spinner label="Loading…" /> : 'No captures saved yet'}
        </div>
      ) : (
        <>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                <th className="px-6 py-2">Filename</th>
                <th className="px-3 py-2">Source</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Owner / Sharing</th>
                <th className="px-3 py-2">Size</th>
                <th className="px-3 py-2">Created</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {pageCaptures.map(c => {
                const isOwner = c.created_by === currentUserId
                return (
                  <tr key={c.id} className="hover:bg-gray-800/30">
                    <td className="px-6 py-3 text-white font-mono text-xs">{c.filename}</td>
                    <td className="px-3 py-3 text-gray-400 text-xs">{c.source}</td>
                    <td className="px-3 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs ${STATUS_STYLES[c.status] ?? STATUS_STYLES.missing}`}>{c.status}</span>
                    </td>
                    <td className="px-3 py-3">
                      {isOwner ? (
                        <label className="flex items-center gap-1.5 text-xs text-gray-300 cursor-pointer">
                          <input type="checkbox" checked={c.shared} onChange={e => onToggleShared(c.filename, e.target.checked)}
                            className="accent-sky-600" />
                          {c.shared ? 'Shared with all users' : 'Private (only you)'}
                        </label>
                      ) : c.created_by === null ? (
                        <span className="text-xs text-gray-500">—</span>
                      ) : c.shared ? (
                        <span className="px-2 py-0.5 rounded text-xs bg-sky-900/40 text-sky-300 border border-sky-700/40">
                          Shared by {c.owner_username ?? 'another user'}
                        </span>
                      ) : (
                        <span className="text-xs text-gray-500">Private (owner: {c.owner_username ?? 'unknown'})</span>
                      )}
                    </td>
                    <td className="px-3 py-3 text-gray-300">{c.size_bytes != null ? fmtBytes(c.size_bytes) : '—'}</td>
                    <td className="px-3 py-3 text-gray-400 text-xs">{fmtTs(c.created_at)}</td>
                    <td className="px-3 py-3">
                      <div className="flex items-center justify-end gap-2">
                        {c.status === 'saved' && <button onClick={() => onAnalyze(c.filename)} className="text-xs text-sky-400 hover:text-sky-300">Analyze</button>}
                        {c.status === 'saved' && <button onClick={() => onDownload(c.filename)} className="text-xs text-gray-400 hover:text-white">Download</button>}
                        {(isAdmin || isOwner || c.created_by === null) && (
                          <button onClick={() => onDelete(c.filename)} className="text-xs text-white hover:text-red-400">Delete</button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>

          <div className="px-4 py-2 border-t border-gray-800">
            <span className="text-xs text-gray-500">
              Showing {((page - 1) * pageSize + 1).toLocaleString()}–{((page - 1) * pageSize + pageCaptures.length).toLocaleString()} of {captures.length.toLocaleString()} captures
            </span>
          </div>
        </>
      )}
    </div>
  )
}
