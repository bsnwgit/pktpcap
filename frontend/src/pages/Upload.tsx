import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, Capture, triggerBrowserDownload } from '../api/client'
import { useAuth } from '../store/auth'
import HelpButton from '../components/HelpButton'
import PersistedCaptures from '../components/PersistedCaptures'
import { fmtBytes } from '../lib/pcap'

export default function Upload() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [files, setFiles] = useState<File[]>([])
  const [shareOnUpload, setShareOnUpload] = useState<Record<string, boolean>>({})
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  const [captures, setCaptures] = useState<Capture[]>([])
  const [storageConfigured, setStorageConfigured] = useState(true)
  const [loadingCaptures, setLoadingCaptures] = useState(true)

  const loadCaptures = () => {
    setLoadingCaptures(true)
    api.getCaptures()
      .then(c => { setCaptures(c.captures); setStorageConfigured(c.storage_path_configured) })
      .catch(e => setError(e.message ?? 'Failed to load captures'))
      .finally(() => setLoadingCaptures(false))
  }
  useEffect(() => { loadCaptures() }, [])

  const addFiles = (incoming: File[]) => {
    setFiles(prev => {
      const existing = new Set(prev.map(f => f.name))
      return [...prev, ...incoming.filter(f => !existing.has(f.name))]
    })
  }

  const removeFile = (name: string) => setFiles(prev => prev.filter(f => f.name !== name))

  // Analyze locally without touching the server at all — the parser runs
  // entirely in the browser, same as the old Flask app's client-side design.
  const analyzeLocally = (file: File) => {
    navigate('/analyzer', { state: { kind: 'upload', file } })
  }

  // Also persist to the server's capture storage, so it shows up later in
  // the Persisted Captures box below (and in Live Feeds → Captures) without
  // re-uploading. shareOnUpload defaults to false — private to the
  // uploader until they explicitly check "Share with other users".
  const saveToServer = async (file: File) => {
    setUploading(true)
    setError('')
    try {
      const res = await api.uploadCapture(file, !!shareOnUpload[file.name])
      loadCaptures()
      navigate('/analyzer', { state: { kind: 'capture', filename: res.filename } })
    } catch (e: any) {
      setError(e.message ?? 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  const analyzeCapture = (filename: string) => navigate('/analyzer', { state: { kind: 'capture', filename } })
  const downloadCapture = async (fname: string) => {
    try { triggerBrowserDownload(await api.downloadCaptureBytes(fname), fname) } catch (e: any) { setError(e.message) }
  }
  const deleteCapture = async (fname: string) => {
    if (!confirm(`Delete ${fname}?`)) return
    try { await api.deleteCapture(fname); loadCaptures() } catch (e: any) { setError(e.message) }
  }
  const toggleCaptureShared = async (fname: string, shared: boolean) => {
    try { await api.setCaptureShared(fname, shared); loadCaptures() } catch (e: any) { setError(e.message) }
  }

  return (
    <div className="space-y-4 max-w-3xl">
      <div className="flex items-center gap-2">
        <h1 className="text-xl font-semibold text-white">Upload Capture</h1>
        <HelpButton title="Upload — How It Works">
          <p><span className="text-gray-300 font-medium">Analyze (local)</span> parses the file entirely in your browser and never sends the bytes anywhere — fastest option, nothing persisted.</p>
          <p><span className="text-gray-300 font-medium">Analyze &amp; Save</span> also uploads the file to the server's configured capture storage (Settings → Captures), so it shows up later in the <span className="text-gray-300 font-medium">Persisted Captures</span> box below.</p>
          <p>Uploads are <span className="text-gray-300 font-medium">private to you by default</span> — check <span className="text-gray-300 font-medium">Share with other users</span> before saving (or toggle it later in the list) to let every signed-in user see and analyze it. Other users' shared captures show up in your own list labeled "Shared by &lt;username&gt;".</p>
        </HelpButton>
      </div>

      <div
        onClick={() => inputRef.current?.click()}
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={e => { e.preventDefault(); setDragging(false); addFiles([...e.dataTransfer.files]) }}
        className={`border-2 rounded-xl p-10 flex flex-col items-center justify-center gap-2 cursor-pointer transition-colors select-none ${
          dragging ? 'border-dashed border-sky-500 bg-sky-500/10' : 'border-gray-800 bg-gray-900 hover:border-gray-700'
        }`}
      >
        <input ref={inputRef} type="file" accept=".pcap,.pcapng,.cap" multiple className="hidden"
          onChange={e => { addFiles([...(e.target.files ?? [])]); e.target.value = '' }} />
        <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m6.75 12H9m1.5-12H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
        </svg>
        <p className="text-sm font-medium text-white">Drop .pcap / .pcapng / .cap files here</p>
        <p className="text-xs text-white">or click to browse</p>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-700/50 rounded-lg px-4 py-2 text-sm text-red-300">{error}</div>
      )}

      {files.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800">
            <h2 className="text-sm font-semibold text-white">Files to Upload</h2>
          </div>
          <div className="divide-y divide-gray-800">
            {files.map(f => (
              <div key={f.name} className="flex items-center gap-3 px-4 py-3">
                <span className="text-lg">📄</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white truncate">{f.name}</p>
                  <p className="text-xs text-gray-500">{fmtBytes(f.size)}</p>
                </div>
                <label className="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer shrink-0">
                  <input type="checkbox" checked={!!shareOnUpload[f.name]}
                    onChange={e => setShareOnUpload(prev => ({ ...prev, [f.name]: e.target.checked }))}
                    className="accent-sky-600" />
                  Share with other users
                </label>
                <button onClick={() => analyzeLocally(f)}
                  className="text-xs px-3 py-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white rounded-lg transition-colors">
                  Analyze (local)
                </button>
                <button onClick={() => saveToServer(f)} disabled={uploading}
                  className="text-xs px-3 py-1.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors">
                  {uploading ? 'Uploading…' : 'Analyze & Save'}
                </button>
                <button onClick={() => removeFile(f.name)} className="text-white hover:text-red-400 text-sm">✕</button>
              </div>
            ))}
          </div>
        </div>
      )}

      <PersistedCaptures
        title="Persisted Captures"
        captures={captures.filter(c => c.source === 'upload')}
        loading={loadingCaptures}
        storageConfigured={storageConfigured}
        currentUserId={user?.id ?? -1}
        isAdmin={isAdmin}
        onAnalyze={analyzeCapture}
        onDownload={downloadCapture}
        onDelete={deleteCapture}
        onToggleShared={toggleCaptureShared}
      />
    </div>
  )
}
