import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { fmtBytes } from '../lib/pcap'

export default function Dashboard() {
  const navigate = useNavigate()
  const [activeFeeds, setActiveFeeds] = useState<number | null>(null)
  const [captureCount, setCaptureCount] = useState<number | null>(null)
  const [totalBytes, setTotalBytes] = useState<number | null>(null)

  useEffect(() => {
    api.getFeeds().then(f => setActiveFeeds(f.filter(s => s.connected).length)).catch(() => setActiveFeeds(0))
    api.getCaptures().then(c => {
      setCaptureCount(c.captures.length)
      setTotalBytes(c.captures.reduce((sum, cap) => sum + (cap.size_bytes ?? 0), 0))
    }).catch(() => { setCaptureCount(0); setTotalBytes(0) })
  }, [])

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-white">pktPCAP</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <p className="text-xs text-gray-500">Active feed sessions</p>
          <p className="text-2xl font-semibold text-white mt-1">{activeFeeds ?? '—'}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <p className="text-xs text-gray-500">Saved captures</p>
          <p className="text-2xl font-semibold text-white mt-1">{captureCount ?? '—'}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <p className="text-xs text-gray-500">Total capture storage</p>
          <p className="text-2xl font-semibold text-white mt-1">{totalBytes != null ? fmtBytes(totalBytes) : '—'}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button onClick={() => navigate('/upload')}
          className="text-left bg-gray-900 border border-gray-800 hover:border-sky-600 rounded-xl p-5 transition-colors">
          <p className="text-sm font-medium text-white">Upload a capture</p>
          <p className="text-xs text-gray-500 mt-1">Analyze a .pcap/.pcapng file — parsed entirely in your browser</p>
        </button>
        <button onClick={() => navigate('/live-feeds')}
          className="text-left bg-gray-900 border border-gray-800 hover:border-sky-600 rounded-xl p-5 transition-colors">
          <p className="text-sm font-medium text-white">Live Feeds</p>
          <p className="text-xs text-gray-500 mt-1">Push a live tshark or Wireshark capture, and manage saved captures</p>
        </button>
        <button onClick={() => navigate('/logs')}
          className="text-left bg-gray-900 border border-gray-800 hover:border-sky-600 rounded-xl p-5 transition-colors">
          <p className="text-sm font-medium text-white">Application Logs</p>
          <p className="text-xs text-gray-500 mt-1">Service startup, feed ingest, and capture save/reconciliation events</p>
        </button>
      </div>
    </div>
  )
}
