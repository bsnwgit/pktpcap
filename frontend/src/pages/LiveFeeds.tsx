import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, FeedSession, Capture, triggerBrowserDownload } from '../api/client'
import { useAuth } from '../store/auth'
import HelpButton from '../components/HelpButton'
import { copyToClipboard } from '../utils/clipboard'
import { fmtBytes } from '../lib/pcap'

// Small standalone toggle so this page doesn't need to import Settings.tsx's
// (deliberately unexported) primitives just for one control.
function InlineToggle({ value, onChange, disabled }: { value: boolean; onChange: () => void; disabled?: boolean }) {
  return (
    <button type="button" onClick={onChange} disabled={disabled}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${value ? 'bg-sky-600' : 'bg-gray-700'}`}>
      <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${value ? 'translate-x-5' : 'translate-x-1'}`} />
    </button>
  )
}

const STATUS_STYLES: Record<string, string> = {
  saved: 'bg-green-900/40 text-green-400 border border-green-700/40',
  saving: 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/40',
  failed: 'bg-red-900/40 text-red-400 border border-red-700/40',
  missing: 'bg-gray-800 text-gray-400 border border-gray-700',
}

function fmtDuration(sec: number): string {
  if (sec < 60) return `${sec.toFixed(0)}s`
  const m = Math.floor(sec / 60)
  const s = Math.floor(sec % 60)
  return `${m}m ${s}s`
}

function fmtTs(ts: string): string {
  try {
    const d = new Date(ts.includes('T') || ts.endsWith('Z') ? ts : ts.replace(' ', 'T') + 'Z')
    return d.toLocaleString()
  } catch {
    return ts
  }
}

// -- Two-tab push-command reference (tshark/curl vs Wireshark SSH) ---------------
// The token appears in the clear inside the generated commands below — it
// has to, or copy-paste-and-run doesn't work. There's no separate "reveal"
// step; anyone who can reach this page (any signed-in user) already needed
// to see it to actually push a capture.
function PushCommands() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [tab, setTab] = useState<'tshark' | 'wireshark'>('tshark')
  const [config, setConfig] = useState<{ wireshark_capture_enabled: boolean; tshark_capture_enabled: boolean; feed_token: string; default_capture_duration_seconds: number } | null>(null)
  const [copied, setCopied] = useState(false)
  const [ownInterfaces, setOwnInterfaces] = useState<string[]>([])
  const [togglingTshark, setTogglingTshark] = useState(false)
  const [togglingWs, setTogglingWs] = useState(false)
  const [sessionName, setSessionName] = useState('my-capture')
  const [ifaceName, setIfaceName] = useState('any')
  const [bpfFilter, setBpfFilter] = useState('')
  const [duration, setDuration] = useState<number | ''>('')
  const [durationTouched, setDurationTouched] = useState(false)

  const loadConfig = () =>
    api.getWrapperConfig().then(cfg => {
      setConfig(cfg)
      // Prefill from the admin-configured default the first time it loads —
      // don't stomp on a value the user already typed in this session.
      if (!durationTouched && cfg.default_capture_duration_seconds > 0) {
        setDuration(cfg.default_capture_duration_seconds)
      }
    }).catch(() => setConfig({ wireshark_capture_enabled: false, tshark_capture_enabled: true, feed_token: '', default_capture_duration_seconds: 0 }))

  useEffect(() => {
    loadConfig()
    api.getNetInterfaces().then(r => setOwnInterfaces(r.interfaces)).catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const toggleTshark = async () => {
    if (!config) return
    setTogglingTshark(true)
    try {
      await api.updateSettings({ tshark_capture_enabled: !config.tshark_capture_enabled })
      await loadConfig()
    } finally {
      setTogglingTshark(false)
    }
  }
  const toggleWireshark = async () => {
    if (!config) return
    setTogglingWs(true)
    try {
      await api.updateSettings({ wireshark_capture_enabled: !config.wireshark_capture_enabled })
      await loadConfig()
    } finally {
      setTogglingWs(false)
    }
  }

  const host = window.location.hostname || 'SERVER-IP'
  const port = window.location.port || '80'
  const token = config?.feed_token || ''

  const name = sessionName.trim() || 'my-capture'
  const iface = ifaceName.trim() || 'any'
  const filter = bpfFilter.trim()
  const filterArg = filter ? ` -f "${filter}"` : ''
  const durationArg = typeof duration === 'number' && duration > 0 ? ` -a duration:${duration}` : ''

  // The command must show the real, working token — it's the whole point of
  // this box (copy-paste-and-run). Masking belongs on a passive display of
  // the token by itself, not on a command that has to actually execute.
  // -a duration:N (when set) lets tshark stop itself instead of relying on
  // Ctrl+C, which kills curl mid-upload and truncates the capture.
  const tsharkCmd = `tshark -i ${iface}${filterArg}${durationArg} -w - | curl -sS -X POST \\\n  -H "Authorization: Bearer ${token || 'YOUR_TOKEN_HERE'}" \\\n  -H "Content-Type: application/octet-stream" \\\n  --data-binary @- \\\n  "http://${host}:${port}/api/feed/${name}"`

  const wsCmd = `SSH Host:   ${host}\nSSH Port:   22\nSSH User:   <your-ssh-user>\nAuth:       SSH Key file (<your-key.pem>)\nCommand:    <install_dir>/pktpcap   (default: /opt/pktpcap/pktpcap)\nInterface:  ${iface}\nFilter:     ${filter || '(none)'}`

  const copy = async (text: string) => {
    const ok = await copyToClipboard(text)
    if (ok) { setCopied(true); setTimeout(() => setCopied(false), 2000) }
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
        <h2 className="text-sm font-semibold text-white">Push a Live Capture</h2>
        <HelpButton title="Push a Live Capture — How It Works">
          <p><span className="text-gray-300 font-medium">tshark / curl</span> works from any host with tshark installed — the interface name is whatever <code className="text-gray-400">tshark -D</code> lists on THAT remote host, which pktPCAP has no way to see in advance, so it stays a free-text field you fill in yourself.</p>
          <p><span className="text-gray-300 font-medium">Wireshark SSH Remote Capture</span> is different: Wireshark SSHes INTO this pktPCAP server and runs the capture here, so the interface list below (this server's own NICs) is the relevant one for that tab only.</p>
          <p>The generated commands include your real feed token — anyone who can push a capture already needs to see it. Treat it like a password: don't paste these commands somewhere untrusted.</p>
          <p><span className="text-gray-300 font-medium">Don't stop a running capture with Ctrl+C</span> — it kills <code className="text-gray-400">curl</code> along with <code className="text-gray-400">tshark</code> in the same keystroke, which usually truncates whatever hadn't uploaded yet (you'll see 0 bytes received even though tshark captured real packets). Set a <span className="text-gray-300 font-medium">Duration</span> below instead, so the capture stops itself and the upload has time to finish.</p>
        </HelpButton>
      </div>
      <div className="px-6 py-4 space-y-4">
        <div className="flex items-end gap-3 flex-wrap">
          <div className="flex-1 min-w-[10rem]">
            <label className="block text-xs text-gray-400 mb-1">Session Name</label>
            <input value={sessionName} onChange={e => setSessionName(e.target.value)} placeholder="e.g. alice-laptop"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
          </div>
          <div className="w-36">
            <label className="block text-xs text-gray-400 mb-1">Interface</label>
            <input value={ifaceName} onChange={e => setIfaceName(e.target.value)} placeholder="e.g. eth0" list="pktpcap-iface-suggestions"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
            <datalist id="pktpcap-iface-suggestions">
              <option value="any" />
              {ownInterfaces.map(i => <option key={i} value={i} />)}
            </datalist>
          </div>
          <div className="w-32">
            <label className="block text-xs text-gray-400 mb-1">Duration (s)</label>
            <input type="number" min={0} value={duration}
              onChange={e => { setDurationTouched(true); const v = e.target.value; setDuration(v === '' ? '' : Number(v)) }}
              placeholder="unlimited"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
          </div>
          <div className="flex-[2] min-w-[12rem]">
            <label className="block text-xs text-gray-400 mb-1">BPF Filter <span className="text-gray-600">(optional)</span></label>
            <input value={bpfFilter} onChange={e => setBpfFilter(e.target.value)} placeholder="e.g. not port 22"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
          </div>
        </div>
        {!duration && (
          <p className="text-xs text-yellow-400 -mt-2">No duration set — you'll need to stop this with Ctrl+C, which can truncate the upload. Set a duration above to avoid that.</p>
        )}

        <div className="flex items-center gap-1 bg-gray-800 border border-gray-700 rounded-lg p-1 w-fit">
          <button onClick={() => setTab('tshark')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${tab === 'tshark' ? 'bg-sky-600 text-white' : 'text-gray-400 hover:text-white'}`}>
            tshark / curl
          </button>
          <button onClick={() => setTab('wireshark')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${tab === 'wireshark' ? 'bg-sky-600 text-white' : 'text-gray-400 hover:text-white'}`}>
            Wireshark SSH Remote Capture
          </button>
        </div>

        <div className="flex items-center gap-2 text-sm">
          {tab === 'tshark' ? (
            <>
              <span className="text-gray-300">Allow tshark / CLI captures</span>
              {config && (
                <InlineToggle value={config.tshark_capture_enabled} onChange={toggleTshark} disabled={!isAdmin || togglingTshark} />
              )}
            </>
          ) : (
            <>
              <span className="text-gray-300">Allow Wireshark SSH Remote Capture</span>
              {config && (
                <InlineToggle value={config.wireshark_capture_enabled} onChange={toggleWireshark} disabled={!isAdmin || togglingWs} />
              )}
            </>
          )}
          {!isAdmin && <span className="text-xs text-gray-500 ml-2">Ask an admin to change this</span>}
        </div>

        {!token && (
          <p className="text-xs text-yellow-400">No feed token set — configure one in Settings → Capture Ingest before using either command below.</p>
        )}

        {tab === 'tshark' ? (
          <div className="space-y-1.5">
            <pre className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-emerald-400 whitespace-pre-wrap overflow-x-auto">{tsharkCmd}</pre>
            <button onClick={() => copy(tsharkCmd)}
              className="text-xs px-3 py-1.5 rounded-lg text-white transition-colors" style={{ background: copied ? '#16a34a' : '#374151' }}>
              {copied ? '✓ Copied' : 'Copy Command'}
            </button>
          </div>
        ) : (
          <div className="space-y-1.5">
            <pre className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-gray-300 whitespace-pre-wrap overflow-x-auto">{wsCmd}</pre>
            <button onClick={() => copy(wsCmd)}
              className="text-xs px-3 py-1.5 rounded-lg text-white transition-colors" style={{ background: copied ? '#16a34a' : '#374151' }}>
              {copied ? '✓ Copied' : 'Copy Settings'}
            </button>
            <p className="text-xs text-gray-500 mt-2">This server's interfaces: {ownInterfaces.length ? ownInterfaces.join(', ') : 'loading…'}</p>
          </div>
        )}
      </div>
    </div>
  )
}

export default function LiveFeeds() {
  const navigate = useNavigate()
  const [feeds, setFeeds] = useState<FeedSession[]>([])
  const [captures, setCaptures] = useState<Capture[]>([])
  const [storageConfigured, setStorageConfigured] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    setError('')
    try {
      const [f, c] = await Promise.all([api.getFeeds(), api.getCaptures()])
      setFeeds(f)
      setCaptures(c.captures)
      setStorageConfigured(c.storage_path_configured)
    } catch (e: any) {
      setError(e.message ?? 'Failed to load')
    } finally {
      if (!silent) setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current)
    if (autoRefresh) timerRef.current = setInterval(() => load(true), 5000)
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [autoRefresh, load])

  const deleteFeed = async (name: string) => {
    try { await api.deleteFeed(name); load() } catch (e: any) { setError(e.message) }
  }
  const deleteCapture = async (fname: string) => {
    if (!confirm(`Delete ${fname}?`)) return
    try { await api.deleteCapture(fname); load() } catch (e: any) { setError(e.message) }
  }
  const analyzeFeed = (name: string) => navigate('/analyzer', { state: { kind: 'feed', name } })
  const analyzeCapture = (filename: string) => navigate('/analyzer', { state: { kind: 'capture', filename } })
  const downloadFeed = async (name: string) => {
    try { triggerBrowserDownload(await api.downloadFeedBytes(name), `${name}.pcapng`) } catch (e: any) { setError(e.message) }
  }
  const downloadCapture = async (fname: string) => {
    try { triggerBrowserDownload(await api.downloadCaptureBytes(fname), fname) } catch (e: any) { setError(e.message) }
  }

  return (
    // pb-20: clearance for the floating AI-assistant button (fixed
    // bottom-6 right-6 in Layout.tsx), which otherwise sits directly over
    // the last row's action links (Delete, etc.) in the Persisted Captures
    // table below.
    <div className="space-y-4 pb-20">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-semibold text-white">Live Feeds</h1>
          <HelpButton title="Live Feeds — How It Works">
            <p><span className="text-gray-300 font-medium">Active Feed Sessions</span> are in-memory only (200MB cap per session) — they disappear on a service restart unless a capture storage path is configured, in which case a finished push is saved to disk automatically.</p>
            <p><span className="text-gray-300 font-medium">Persisted Captures</span> are the saved files, tracked with a real status (saving/saved/failed/missing) so a crash mid-write is visible instead of silently absent.</p>
          </HelpButton>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoRefresh(v => !v)}
            className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${autoRefresh ? 'bg-sky-600/20 border-sky-500/50 text-sky-300' : 'bg-gray-800 border-gray-700 text-gray-300 hover:text-white'}`}
          >
            {autoRefresh ? 'Live' : 'Auto-refresh off'}
          </button>
          <button onClick={() => load()} disabled={loading}
            className="text-xs px-3 py-1.5 bg-gray-800 border border-gray-700 text-gray-300 hover:text-white rounded-lg transition-colors disabled:opacity-50">
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {error && <div className="bg-red-900/30 border border-red-700/50 rounded-lg px-4 py-2 text-sm text-red-300">{error}</div>}

      <PushCommands />

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-white">Active Feed Sessions</h2>
        </div>
        {feeds.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-gray-500">No active feed sessions</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                <th className="px-6 py-2">Name</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Remote</th>
                <th className="px-3 py-2">Bytes</th>
                <th className="px-3 py-2">Duration</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {feeds.map(f => (
                <tr key={f.name} className="hover:bg-gray-800/30">
                  <td className="px-6 py-3 text-white font-mono text-xs">{f.name}{f.truncated && <span className="ml-1 text-yellow-400" title="Buffer cap (200MB) reached — truncated">⚠</span>}</td>
                  <td className="px-3 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${f.connected ? 'bg-green-900/40 text-green-400 border border-green-700/40' : 'bg-gray-800 text-gray-400 border border-gray-700'}`}>
                      {f.connected ? 'streaming' : 'idle'}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-gray-400 font-mono text-xs">{f.remote_addr}</td>
                  <td className="px-3 py-3 text-gray-300">{fmtBytes(f.bytes_received)}</td>
                  <td className="px-3 py-3 text-gray-300">{fmtDuration(f.duration)}</td>
                  <td className="px-3 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button onClick={() => analyzeFeed(f.name)} className="text-xs text-sky-400 hover:text-sky-300">Analyze</button>
                      <button onClick={() => downloadFeed(f.name)} className="text-xs text-gray-400 hover:text-white">Download</button>
                      <button onClick={() => deleteFeed(f.name)} className="text-xs text-white hover:text-red-400">Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Persisted Captures</h2>
          {!storageConfigured && (
            <span className="text-xs text-yellow-400">No storage path configured — captures aren't saved to disk. Set one in Settings → Captures.</span>
          )}
        </div>
        {captures.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-gray-500">No captures saved yet</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                <th className="px-6 py-2">Filename</th>
                <th className="px-3 py-2">Source</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Size</th>
                <th className="px-3 py-2">Created</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {captures.map(c => (
                <tr key={c.id} className="hover:bg-gray-800/30">
                  <td className="px-6 py-3 text-white font-mono text-xs">{c.filename}</td>
                  <td className="px-3 py-3 text-gray-400 text-xs">{c.source}</td>
                  <td className="px-3 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${STATUS_STYLES[c.status] ?? STATUS_STYLES.missing}`}>{c.status}</span>
                  </td>
                  <td className="px-3 py-3 text-gray-300">{c.size_bytes != null ? fmtBytes(c.size_bytes) : '—'}</td>
                  <td className="px-3 py-3 text-gray-400 text-xs">{fmtTs(c.created_at)}</td>
                  <td className="px-3 py-3">
                    <div className="flex items-center justify-end gap-2">
                      {c.status === 'saved' && <button onClick={() => analyzeCapture(c.filename)} className="text-xs text-sky-400 hover:text-sky-300">Analyze</button>}
                      {c.status === 'saved' && <button onClick={() => downloadCapture(c.filename)} className="text-xs text-gray-400 hover:text-white">Download</button>}
                      <button onClick={() => deleteCapture(c.filename)} className="text-xs text-white hover:text-red-400">Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
