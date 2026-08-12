import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, FeedSession, Capture, triggerBrowserDownload } from '../api/client'
import { useAuth } from '../store/auth'
import HelpButton from '../components/HelpButton'
import Spinner from '../components/Spinner'
import PersistedCaptures from '../components/PersistedCaptures'
import { copyToClipboard } from '../utils/clipboard'
import { fmtBytes } from '../lib/pcap'

// Browses THIS pktPCAP server's filesystem (admin-only /api/system/browse-fs)
// so the Remote Command field can be filled by picking the real binary
// instead of typing a path blind. Unlike the SSH Key File field below, this
// path lives on a server we control, so a real directory listing works —
// no browser sandboxing limitation applies here.
function ServerFileBrowserModal({ initialPath, onSelect, onClose }: {
  initialPath: string; onSelect: (path: string) => void; onClose: () => void
}) {
  const [path, setPath] = useState(initialPath)
  const [pathInput, setPathInput] = useState(initialPath)
  const [entries, setEntries] = useState<Array<{ name: string; path: string; is_dir: boolean }>>([])
  const [parent, setParent] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = (p: string) => {
    setLoading(true)
    setError('')
    api.browseFs(p)
      .then(r => { setPath(r.path); setPathInput(r.path); setEntries(r.entries); setParent(r.parent) })
      .catch(e => setError(e.message ?? 'Failed to browse'))
      .finally(() => setLoading(false))
  }
  useEffect(() => { load(initialPath) }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-lg p-6" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-white mb-4">Browse Server Files</h2>
        <form onSubmit={e => { e.preventDefault(); load(pathInput) }} className="flex items-center gap-2 mb-3">
          <input value={pathInput} onChange={e => setPathInput(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white font-mono focus:outline-none focus:ring-2 focus:ring-sky-500" />
          <button type="submit" className="shrink-0 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white text-sm font-medium rounded-lg px-3 py-1.5">Go</button>
        </form>
        {error && <p className="text-xs text-red-400 mb-2">{error}</p>}
        <div className="border border-gray-800 rounded-lg h-72 overflow-y-auto">
          {loading ? (
            <p className="text-sm text-gray-500 p-4">Loading…</p>
          ) : (
            <div className="divide-y divide-gray-800/60">
              {parent !== null && (
                <button onClick={() => load(parent)} className="w-full text-left px-3 py-2 text-sm text-gray-400 hover:bg-gray-800/50">.. (up a directory)</button>
              )}
              {entries.length === 0 && parent === null && (
                <p className="text-sm text-gray-500 p-4">Empty directory</p>
              )}
              {entries.map(e => (
                <button key={e.path}
                  onClick={() => e.is_dir ? load(e.path) : onSelect(e.path)}
                  className="w-full text-left px-3 py-2 text-sm text-white hover:bg-gray-800/50 flex items-center gap-2">
                  <span className="text-gray-500">{e.is_dir ? '📁' : '📄'}</span>
                  {e.name}
                </button>
              ))}
            </div>
          )}
        </div>
        <div className="flex items-center justify-between mt-4">
          <p className="text-xs text-gray-500">Click a folder to open it, a file to select it.</p>
          <div className="flex items-center gap-2">
            <button onClick={() => onSelect(path)} className="text-xs px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white font-medium rounded-lg">Use This Folder</button>
            <button onClick={onClose} className="text-xs px-3 py-1.5 bg-gray-800 border border-gray-700 text-gray-300 hover:text-white rounded-lg">Cancel</button>
          </div>
        </div>
      </div>
    </div>
  )
}

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

function fmtDuration(sec: number): string {
  if (sec < 60) return `${sec.toFixed(0)}s`
  const m = Math.floor(sec / 60)
  const s = Math.floor(sec % 60)
  return `${m}m ${s}s`
}

// -- Three-tab push-command reference: tshark/curl, Wireshark CLI (sshdump
// launched straight from a terminal), and Wireshark UI (the same sshdump
// setup walked through Wireshark's own settings dialog) --------------------
// The token appears in the clear inside the generated commands below — it
// has to, or copy-paste-and-run doesn't work. There's no separate "reveal"
// step; anyone who can reach this page (any signed-in user) already needed
// to see it to actually push a capture.
function PushCommands() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [tab, setTab] = useState<'tshark' | 'wireshark-cli' | 'wireshark-ui'>('tshark')
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
  // Wireshark SSH Remote Capture connection params — these mirror the exact
  // fields Wireshark's own "Manage Remote Interfaces" dialog asks for, so a
  // user can fill them in here once and copy the finished values straight
  // into that dialog instead of hand-editing placeholders in a text block.
  const [sshHost, setSshHost] = useState('')
  const [sshHostTouched, setSshHostTouched] = useState(false)
  const [sshPort, setSshPort] = useState('22')
  const [sshUser, setSshUser] = useState('')
  const [sshKeyPath, setSshKeyPath] = useState('')
  const [keyDragOver, setKeyDragOver] = useState(false)
  const keyFileInputRef = useRef<HTMLInputElement>(null)
  const [command, setCommand] = useState('')
  const [commandTouched, setCommandTouched] = useState(false)
  const [browsingCommand, setBrowsingCommand] = useState(false)

  // Browsers never expose a locally-picked file's real folder path (only
  // its bare name) — a deliberate privacy restriction, not a bug here or
  // in "other sites" that appear to do more. Take whatever we can (the
  // filename) and drop it into the existing path if there is one, so the
  // user only has to fix up the directory instead of retyping everything.
  const applyPickedKeyFilename = (filename: string) => {
    setSshKeyPath(prev => {
      const slash = Math.max(prev.lastIndexOf('/'), prev.lastIndexOf('\\'))
      return slash >= 0 ? prev.slice(0, slash + 1) + filename : filename
    })
  }

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
    if (!sshHostTouched) setSshHost(window.location.hostname || 'SERVER-IP')
    api.getSystemInfo().then(info => {
      if (!commandTouched) setCommand(`${info.install_dir}/pktpcap`)
    }).catch(() => {})
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
  // -T - (not --data-binary @-): curl's --data-binary reads all of stdin
  // into memory to compute a Content-Length before sending anything, so the
  // whole capture uploads in one burst at the very end — it never appears
  // as an active feed session while running. -T - uses chunked
  // Transfer-Encoding and streams each chunk as tshark produces it, so the
  // session shows up live in Active Feed Sessions immediately. -T defaults
  // to PUT, hence the explicit -X POST override.
  // ?owner=<user.id> attributes the resulting persisted capture to whoever
  // copies this command (see app/api/feeds.py's receive_feed docstring) —
  // purely for the captures-sharing feature, not an auth control.
  const tsharkCmd = `tshark -i ${iface}${filterArg}${durationArg} -w - | curl -sS -X POST \\\n  -H "Authorization: Bearer ${token || 'YOUR_TOKEN_HERE'}" \\\n  -T - \\\n  "http://${host}:${port}/api/feed/${name}?owner=${user?.id ?? ''}"`

  // Wireshark's SSH remote capture (the "sshdump" extcap) runs the Remote
  // Capture Command exactly as given — it does NOT append the Remote
  // Interface or Remote Filter fields for you (confirmed against sshdump's
  // own docs: https://www.wireshark.org/docs/man-pages/sshdump.html — "this
  // command will be used as is"). So interface + filter have to be baked
  // into the command string itself, both for the CLI form below and for
  // the "Remote Capture Command" field in the GUI walkthrough tab.
  const wsFilterArg = filter ? ` -f '${filter}'` : ''
  const wsRemoteCommand = `${command || '<install_dir>/pktpcap'} -i ${iface}${wsFilterArg} -w -`

  // Launches Wireshark itself from the CLI with sshdump pre-configured via
  // -o extcap.sshdump.<option>:"<value>" preference overrides, and -k to
  // start capturing immediately — verified against Wireshark's own docs
  // (ask.wireshark.org/question/2506) rather than guessed, since a wrong
  // preference key here would just silently fail to configure anything.
  const wsCliCmd = `wireshark -k -i sshdump \\\n  -oextcap.sshdump.remotehost:"${sshHost || 'SERVER-IP'}" \\\n  -oextcap.sshdump.remoteport:"${sshPort || '22'}" \\\n  -oextcap.sshdump.remoteusername:"${sshUser || '<your-ssh-user>'}" \\\n  -oextcap.sshdump.sshkey:"${sshKeyPath || '<your-key.pem>'}" \\\n  -oextcap.sshdump.remotecapturecommand:"${wsRemoteCommand}"`

  const wsUiSummary = `SSH Host:              ${sshHost || 'SERVER-IP'}\nSSH Port:              ${sshPort || '22'}\nSSH Username:          ${sshUser || '<your-ssh-user>'}\nSSH Auth:              Key file (${sshKeyPath || '<your-key.pem>'})\nRemote Capture Command: ${wsRemoteCommand}`

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
          <p><span className="text-gray-300 font-medium">Wireshark CLI</span> and <span className="text-gray-300 font-medium">Wireshark UI</span> both use the same underlying mechanism — Wireshark's SSH remote capture ("sshdump") SSHes INTO this pktPCAP server and runs the capture here, so the interface list below (this server's own NICs) is the relevant one for both tabs. CLI launches Wireshark pre-configured from a terminal (<code className="text-gray-400">wireshark -k -i sshdump -o ...</code>); UI walks through the same fields in Wireshark's own settings dialog.</p>
          <p>The generated commands include your real feed token — anyone who can push a capture already needs to see it. Treat it like a password: don't paste these commands somewhere untrusted.</p>
          <p><span className="text-gray-300 font-medium">Don't stop a running capture with Ctrl+C</span> — it kills <code className="text-gray-400">curl</code> along with <code className="text-gray-400">tshark</code> in the same keystroke, which usually truncates whatever hadn't uploaded yet (you'll see 0 bytes received even though tshark captured real packets). Set a <span className="text-gray-300 font-medium">Duration</span> below instead, so the capture stops itself and the upload has time to finish.</p>
          <p><span className="text-gray-300 font-medium">Wireshark showing a red "Error from extcap pipe" message when you stop a capture is expected</span> — Wireshark echoes back harmless SSH connection warnings and mislabels them as an error. It's a known Wireshark bug on your own machine, not a pktPCAP problem, and doesn't mean the capture failed.</p>
        </HelpButton>
      </div>
      <div className="px-6 py-4 space-y-4">
        <div className="flex items-center gap-1 bg-gray-800 border border-gray-700 rounded-lg p-1 w-fit">
          <button onClick={() => setTab('tshark')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${tab === 'tshark' ? 'bg-sky-600 text-white' : 'text-gray-400 hover:text-white'}`}>
            tshark / curl
          </button>
          <button onClick={() => setTab('wireshark-cli')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${tab === 'wireshark-cli' ? 'bg-sky-600 text-white' : 'text-gray-400 hover:text-white'}`}>
            Wireshark CLI
          </button>
          <button onClick={() => setTab('wireshark-ui')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${tab === 'wireshark-ui' ? 'bg-sky-600 text-white' : 'text-gray-400 hover:text-white'}`}>
            Wireshark UI
          </button>
        </div>

        {/* Inputs are tailored per tab: tshark/curl pushes from a remote
            host we can't see, so Session Name + Duration are user-supplied
            and the Interface field is free-text. Wireshark SSH Remote
            Capture runs dumpcap on THIS server — the session name is
            auto-generated by the wrapper script (ws-<ip>-<time>) and the
            capture duration is controlled by Wireshark's own capture
            options, not this page, so only Interface (picked from this
            server's real NICs) and a reference Filter apply. */}
        {tab !== 'tshark' && (
          <div className="flex items-end gap-3 flex-wrap">
            <div className="w-40">
              <label className="block text-xs text-gray-400 mb-1">SSH Host</label>
              <input value={sshHost} onChange={e => { setSshHostTouched(true); setSshHost(e.target.value) }}
                placeholder="e.g. 10.20.30.21"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
            </div>
            <div className="w-24">
              <label className="block text-xs text-gray-400 mb-1">SSH Port</label>
              <input value={sshPort} onChange={e => setSshPort(e.target.value)} placeholder="22"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
            </div>
            <div className="w-32">
              <label className="block text-xs text-gray-400 mb-1">SSH User</label>
              <input value={sshUser} onChange={e => setSshUser(e.target.value)} placeholder="e.g. robert"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
            </div>
            <div className="flex-1 min-w-[14rem]">
              <label className="block text-xs text-gray-400 mb-1">SSH Key File <span className="text-gray-600">(on your machine)</span></label>
              <div
                onDragOver={e => { e.preventDefault(); setKeyDragOver(true) }}
                onDragLeave={() => setKeyDragOver(false)}
                onDrop={e => {
                  e.preventDefault()
                  setKeyDragOver(false)
                  const f = e.dataTransfer.files?.[0]
                  if (f) applyPickedKeyFilename(f.name)
                }}
                className={`flex items-center gap-1.5 rounded-lg border ${keyDragOver ? 'border-sky-500 bg-sky-950/30' : 'border-gray-700 bg-gray-800'}`}
              >
                <input value={sshKeyPath} onChange={e => setSshKeyPath(e.target.value)} placeholder="Drag a file here, browse, or type a path"
                  className="w-full bg-transparent px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none" />
                <button type="button" onClick={() => keyFileInputRef.current?.click()}
                  className="shrink-0 mr-1 text-xs px-2 py-1 bg-gray-700 hover:bg-gray-600 text-white rounded-md">
                  Browse…
                </button>
                <input ref={keyFileInputRef} type="file" className="hidden"
                  onChange={e => { const f = e.target.files?.[0]; if (f) applyPickedKeyFilename(f.name); e.target.value = '' }} />
              </div>
            </div>
            <div className="flex-1 min-w-[14rem]">
              <label className="block text-xs text-gray-400 mb-1">Remote Command <span className="text-gray-600">(on this server)</span></label>
              <div className="flex items-center gap-1.5">
                <input value={command} onChange={e => { setCommandTouched(true); setCommand(e.target.value) }}
                  placeholder="e.g. /opt/pktpcap/pktpcap"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
                {isAdmin && (
                  <button type="button" onClick={() => setBrowsingCommand(true)}
                    className="shrink-0 text-xs px-2 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded-md">
                    Browse…
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
        {browsingCommand && (
          <ServerFileBrowserModal
            initialPath={command || '/'}
            onSelect={p => { setCommandTouched(true); setCommand(p); setBrowsingCommand(false) }}
            onClose={() => setBrowsingCommand(false)}
          />
        )}
        <div className="flex items-end gap-3 flex-wrap">
          {tab === 'tshark' && (
            <div className="flex-1 min-w-[10rem]">
              <label className="block text-xs text-gray-400 mb-1">Session Name</label>
              <input value={sessionName} onChange={e => setSessionName(e.target.value)} placeholder="e.g. alice-laptop"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
            </div>
          )}
          <div className="w-36">
            <label className="block text-xs text-gray-400 mb-1">
              {tab === 'tshark' ? 'Interface (remote host)' : 'Interface (this server)'}
            </label>
            <input value={ifaceName} onChange={e => setIfaceName(e.target.value)}
              placeholder={tab === 'tshark' ? 'e.g. eth0' : 'e.g. any'} list="pktpcap-iface-suggestions"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
            <datalist id="pktpcap-iface-suggestions">
              <option value="any" />
              {ownInterfaces.map(i => <option key={i} value={i} />)}
            </datalist>
          </div>
          {tab === 'tshark' && (
            <div className="w-32">
              <label className="block text-xs text-gray-400 mb-1">Duration (s)</label>
              <input type="number" min={0} value={duration}
                onChange={e => { setDurationTouched(true); const v = e.target.value; setDuration(v === '' ? '' : Number(v)) }}
                placeholder="unlimited"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
            </div>
          )}
          <div className="flex-[2] min-w-[12rem]">
            <label className="block text-xs text-gray-400 mb-1">
              BPF Filter {tab === 'tshark' ? <span className="text-gray-600">(optional)</span> : <span className="text-gray-600">(baked into the command below, optional)</span>}
            </label>
            <input value={bpfFilter} onChange={e => setBpfFilter(e.target.value)} placeholder="e.g. not port 22"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sky-500" />
          </div>
        </div>
        {tab === 'tshark' && !duration && (
          <p className="text-xs text-yellow-400 -mt-2">No duration set — you'll need to stop this with Ctrl+C, which can truncate the upload. Set a duration above to avoid that.</p>
        )}
        {tab !== 'tshark' && (
          <p className="text-xs text-gray-500 -mt-2">Session name and capture duration aren't set here — the wrapper script names the session automatically, and Wireshark's own capture options control how long it runs.</p>
        )}

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
          <p className="text-xs text-yellow-400">No feed token set — configure one in Settings → Capture Ingest before using any command below.</p>
        )}

        {tab === 'tshark' && (
          <div className="space-y-1.5">
            <pre className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-emerald-400 whitespace-pre-wrap overflow-x-auto">{tsharkCmd}</pre>
            <button onClick={() => copy(tsharkCmd)}
              className="text-xs px-3 py-1.5 rounded-lg text-white transition-colors" style={{ background: copied ? '#52cc8e' : '#2a2418' }}>
              {copied ? '✓ Copied' : 'Copy Command'}
            </button>
          </div>
        )}

        {tab === 'wireshark-cli' && (
          <div className="space-y-1.5">
            <p className="text-xs text-gray-500">Run this on the machine that has Wireshark installed (not on the pktPCAP server) — it launches Wireshark and starts capturing immediately over SSH:</p>
            <pre className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-emerald-400 whitespace-pre-wrap overflow-x-auto">{wsCliCmd}</pre>
            <button onClick={() => copy(wsCliCmd)}
              className="text-xs px-3 py-1.5 rounded-lg text-white transition-colors" style={{ background: copied ? '#52cc8e' : '#2a2418' }}>
              {copied ? '✓ Copied' : 'Copy Command'}
            </button>
            <p className="text-xs text-gray-500 mt-2">This server's interfaces: {ownInterfaces.length ? ownInterfaces.join(', ') : 'loading…'}</p>
            <WiresharkStopNotice />
          </div>
        )}

        {tab === 'wireshark-ui' && (
          <div className="space-y-3">
            <ol className="list-decimal list-inside text-xs text-gray-300 space-y-1.5">
              <li>In Wireshark's main interface list, look for <span className="text-white font-medium">SSH remote capture: sshdump</span>. If it's missing, re-run the Wireshark installer and enable the "sshdump" component under Tools.</li>
              <li>Click the small gear/wrench icon next to that entry to open its settings.</li>
              <li>Fill in <span className="text-white font-medium">Remote SSH server address</span>, <span className="text-white font-medium">port</span>, and <span className="text-white font-medium">username</span> using the SSH Host/Port/User fields above.</li>
              <li>Under Authentication, choose <span className="text-white font-medium">SSH public key</span> and browse to the key file from the SSH Key File field above (or Password, if that's how this server is set up).</li>
              <li>Paste the line below into <span className="text-white font-medium">Remote Capture Command</span> exactly as shown — it already has the interface and filter baked in. (Some Wireshark versions ignore the separate Remote Interface / Remote Capture Filter fields, so this is the reliable way.)</li>
              <li>Click Save, then select the sshdump interface in the main list and click Start.</li>
            </ol>
            <pre className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-emerald-400 whitespace-pre-wrap overflow-x-auto">{wsRemoteCommand}</pre>
            <button onClick={() => copy(wsRemoteCommand)}
              className="text-xs px-3 py-1.5 rounded-lg text-white transition-colors" style={{ background: copied ? '#52cc8e' : '#2a2418' }}>
              {copied ? '✓ Copied' : 'Copy Remote Capture Command'}
            </button>
            <p className="text-xs text-gray-500 mb-1">All fields together, for reference:</p>
            <pre className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-gray-300 whitespace-pre-wrap overflow-x-auto">{wsUiSummary}</pre>
            <p className="text-xs text-gray-500 mt-2">This server's interfaces: {ownInterfaces.length ? ownInterfaces.join(', ') : 'loading…'}</p>
            <WiresharkStopNotice />
          </div>
        )}
      </div>
    </div>
  )
}

// Wireshark prints an "Error from extcap pipe" banner whenever it stops a
// capture, echoing back whatever sshdump wrote to stderr during connection
// setup — even when that output was only informational libssh warnings
// (e.g. "Unsupported option: ..." from parsing ~/.ssh/config). This is a
// known, filed Wireshark display quirk (gitlab.com/wireshark/wireshark/
// -/issues/15845), not a pktPCAP problem and not a sign the capture failed
// — it's purely client-side, on whatever machine runs Wireshark, and
// pktPCAP has no way to suppress or influence it.
function WiresharkStopNotice() {
  return (
    <div className="mt-2 bg-amber-950/30 border border-amber-800/40 rounded-lg px-3 py-2">
      <p className="text-xs text-amber-300">
        <span className="font-medium">Expected:</span> when you stop the capture, Wireshark may show a red <span className="font-mono">"Error from extcap pipe"</span> message. This is <span className="font-medium">Wireshark itself</span> echoing back harmless connection-setup warnings (e.g. SSH config parsing notices) — it is not a pktPCAP error and does not mean the capture failed. It's a{' '}
        <a href="https://gitlab.com/wireshark/wireshark/-/issues/15845" target="_blank" rel="noreferrer" className="underline hover:text-amber-200">known Wireshark display quirk</a>, purely client-side, that pktPCAP has no ability to change.
      </p>
    </div>
  )
}

export default function LiveFeeds() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
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
  const toggleCaptureShared = async (fname: string, shared: boolean) => {
    try { await api.setCaptureShared(fname, shared); load() } catch (e: any) { setError(e.message) }
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
    <div className="space-y-4">
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
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-gray-800 border border-gray-700 text-gray-300 hover:text-white rounded-lg transition-colors disabled:opacity-50">
            {loading && <Spinner className="w-3 h-3" />}
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
          <div className="px-6 py-8 text-center text-sm text-gray-500">
            {loading ? <Spinner label="Loading…" /> : 'No active feed sessions'}
          </div>
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

      <PersistedCaptures
        title="Persisted Captures"
        captures={captures.filter(c => c.source !== 'upload')}
        loading={loading}
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
