import { useEffect, useMemo, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import HelpButton from '../components/HelpButton'
import IpLink, { linkifyIps } from '../components/IpLink'
import { parsePCAP, analyzePackets, fmtBytes, safeIso, type AnalysisResult } from '../lib/pcap'

type LocationState =
  | { kind: 'upload'; file: File }
  | { kind: 'capture'; filename: string }
  | { kind: 'feed'; name: string }
  | undefined

const TABS = ['summary', 'anomalies', 'flows', 'tcp', 'udp', 'dns', 'threats'] as const
type TabId = typeof TABS[number]

const TAB_LABELS: Record<TabId, string> = {
  summary: 'Summary', anomalies: 'Anomalies', flows: 'Flows',
  tcp: 'TCP', udp: 'UDP', dns: 'DNS', threats: 'Threats',
}

const SEVERITY_STYLES: Record<string, string> = {
  high: 'bg-red-900/40 text-red-400 border border-red-700/40',
  medium: 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/40',
  low: 'bg-gray-800 text-gray-400 border border-gray-700',
}

function readFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(reader.result as ArrayBuffer)
    reader.onerror = () => reject(reader.error ?? new Error('Failed to read file'))
    reader.readAsArrayBuffer(file)
  })
}

export default function Analyzer() {
  const location = useLocation()
  const navigate = useNavigate()
  const state = location.state as LocationState

  const [label, setLabel] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [tab, setTab] = useState<TabId>('summary')

  useEffect(() => {
    let cancelled = false

    async function run() {
      if (!state) { setLoading(false); return }
      setLoading(true)
      setError('')
      try {
        let buf: ArrayBuffer
        let name: string
        if (state.kind === 'upload') {
          name = state.file.name
          buf = await readFileAsArrayBuffer(state.file)
        } else if (state.kind === 'capture') {
          name = state.filename
          buf = await (await api.downloadCaptureBytes(state.filename)).arrayBuffer()
        } else {
          name = state.name
          buf = await (await api.downloadFeedBytes(state.name)).arrayBuffer()
        }
        if (cancelled) return
        setLabel(name)
        const packets = parsePCAP(buf, name)
        const analysis = analyzePackets(packets)
        if (!analysis) throw new Error('No packets found in this capture')
        setResult(analysis)
      } catch (e: any) {
        if (!cancelled) setError(e.message ?? 'Failed to analyze capture')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    run()
    return () => { cancelled = true }
  }, [state])

  const maxProtoCount = useMemo(() => result ? Math.max(...result.protocols.map(([, c]) => c), 1) : 1, [result])
  const maxTalkerBytes = useMemo(() => result ? Math.max(...result.topTalkers.map(([, b]) => b), 1) : 1, [result])

  if (!state) {
    return (
      <div className="max-w-lg mx-auto text-center py-16 space-y-4">
        <p className="text-white text-lg">No capture selected</p>
        <p className="text-sm text-gray-400">Upload a file or pick a capture/feed from Live Feeds to analyze it here.</p>
        <div className="flex items-center justify-center gap-3">
          <button onClick={() => navigate('/upload')} className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white text-sm rounded-lg">Upload</button>
          <button onClick={() => navigate('/live-feeds')} className="px-4 py-2 bg-gray-800 border border-gray-700 text-white text-sm rounded-lg">Live Feeds</button>
        </div>
      </div>
    )
  }

  if (loading) return <div className="flex items-center justify-center h-48 text-white text-sm">Parsing {label || 'capture'}…</div>
  if (error) return <div className="bg-red-900/30 border border-red-700/50 rounded-lg px-4 py-3 text-sm text-red-300 max-w-lg mx-auto mt-8">{error}</div>
  if (!result) return null

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <h1 className="text-xl font-semibold text-white truncate">{label}</h1>
        <HelpButton title="Analyzer — How It Works">
          <p>Parsing runs entirely in your browser — the pcap/pcapng bytes never touch an external service, whether from an upload, a saved capture, or a live feed's buffered bytes.</p>
          <p><span className="text-gray-300 font-medium">Threats</span> and <span className="text-gray-300 font-medium">Anomalies</span> are heuristic pattern matches (port scans, cleartext protocols, retransmission rates, etc.) — treat them as leads to investigate, not confirmed findings.</p>
        </HelpButton>
      </div>

      <div className="flex items-center gap-1 bg-gray-900 border border-gray-800 rounded-xl p-1 w-fit overflow-x-auto">
        {TABS.map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`text-sm px-4 py-1.5 rounded-lg whitespace-nowrap transition-colors ${tab === t ? 'bg-gray-700 text-white' : 'text-white hover:text-white'}`}>
            {TAB_LABELS[t]}
            {t === 'anomalies' && result.anomalies.length > 0 && <span className="ml-1.5 text-xs text-yellow-400">{result.anomalies.length}</span>}
            {t === 'threats' && result.security.summary.total > 0 && <span className="ml-1.5 text-xs text-red-400">{result.security.summary.total}</span>}
          </button>
        ))}
      </div>

      {tab === 'summary' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              ['Packets', result.metadata.totalPackets.toLocaleString()],
              ['Duration', `${result.metadata.duration}s`],
              ['Rate', `${result.metadata.pps} pkt/s`],
              ['Total Size', fmtBytes(result.metadata.totalBytes)],
            ].map(([label, value]) => (
              <div key={label} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <p className="text-xs text-gray-500">{label}</p>
                <p className="text-lg font-semibold text-white mt-1">{value}</p>
              </div>
            ))}
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500">Capture window</p>
            <p className="text-sm text-white mt-1">{result.metadata.firstTs} → {result.metadata.lastTs}</p>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-800"><h2 className="text-sm font-semibold text-white">Protocol Breakdown</h2></div>
            <div className="px-6 py-4 space-y-2">
              {result.protocols.map(([proto, count]) => (
                <div key={proto} className="flex items-center gap-3">
                  <span className="w-20 text-xs text-gray-300 truncate">{proto}</span>
                  <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
                    <div className="bg-sky-600 h-2 rounded-full" style={{ width: `${(count / maxProtoCount) * 100}%` }} />
                  </div>
                  <span className="w-16 text-right text-xs text-gray-400">{count.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-800"><h2 className="text-sm font-semibold text-white">Top Talkers</h2></div>
            <div className="px-6 py-4 space-y-2">
              {result.topTalkers.map(([ip, bytes]) => (
                <div key={ip} className="flex items-center gap-3">
                  <span className="w-32 text-xs font-mono text-gray-300 truncate"><IpLink ip={ip} /></span>
                  <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
                    <div className="bg-emerald-600 h-2 rounded-full" style={{ width: `${(bytes / maxTalkerBytes) * 100}%` }} />
                  </div>
                  <span className="w-20 text-right text-xs text-gray-400">{fmtBytes(bytes)}</span>
                </div>
              ))}
              {result.topTalkers.length === 0 && <p className="text-sm text-gray-500">No IP traffic found</p>}
            </div>
          </div>
        </div>
      )}

      {tab === 'anomalies' && (
        <div className="space-y-3">
          {result.anomalies.length === 0 ? (
            <div className="bg-gray-900 border border-gray-800 rounded-xl px-6 py-8 text-center text-sm text-gray-500">No anomalies detected</div>
          ) : result.anomalies.map((a, i) => (
            <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-1">
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_STYLES[a.severity]}`}>{a.severity}</span>
                <p className="text-sm font-medium text-white">{a.type}</p>
              </div>
              <p className="text-sm text-gray-300 mb-2">{a.detail}</p>
              {a.evidence.length > 0 && (
                <ul className="text-xs text-gray-500 space-y-0.5 font-mono">
                  {a.evidence.map((e, j) => <li key={j}>• {linkifyIps(e)}</li>)}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}

      {tab === 'flows' && (
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-800"><h2 className="text-sm font-semibold text-white">Conversations ({result.conversations.length})</h2></div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                    <th className="px-6 py-2">Flow</th><th className="px-3 py-2">Packets</th><th className="px-3 py-2">Bytes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60">
                  {result.conversations.map(c => (
                    <tr key={c.normKey} className="hover:bg-gray-800/30">
                      <td className="px-6 py-2 text-white font-mono text-xs">{linkifyIps(c.display)}</td>
                      <td className="px-3 py-2 text-gray-300">{c.pkts.toLocaleString()}</td>
                      <td className="px-3 py-2 text-gray-300">{fmtBytes(c.bytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-800"><h2 className="text-sm font-semibold text-white">Ports ({result.ports.length})</h2></div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                    <th className="px-6 py-2">Port</th><th className="px-3 py-2">Protocol</th><th className="px-3 py-2">Packets</th><th className="px-3 py-2">Bytes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60">
                  {result.ports.map(p => (
                    <tr key={`${p.proto}-${p.port}`} className="hover:bg-gray-800/30">
                      <td className="px-6 py-2 text-white font-mono text-xs">{p.port}</td>
                      <td className="px-3 py-2 text-gray-400 text-xs">{p.proto}</td>
                      <td className="px-3 py-2 text-gray-300">{p.pkts.toLocaleString()}</td>
                      <td className="px-3 py-2 text-gray-300">{fmtBytes(p.bytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {tab === 'tcp' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              ['RSTs', result.tcpStats.totalRsts],
              ['Failed Handshakes', result.tcpStats.failedHandshakes],
              ['Retransmissions', result.tcpStats.totalRetrans],
              ['Zero Windows', result.tcpStats.totalZeroWin],
            ].map(([label, value]) => (
              <div key={label as string} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <p className="text-xs text-gray-500">{label}</p>
                <p className="text-lg font-semibold text-white mt-1">{value}</p>
              </div>
            ))}
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-800"><h2 className="text-sm font-semibold text-white">Streams with issues</h2></div>
            {result.tcpStats.issueStreams.length === 0 ? (
              <div className="px-6 py-8 text-center text-sm text-gray-500">No problematic TCP streams found</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                      <th className="px-6 py-2">Stream</th><th className="px-3 py-2">RSTs</th><th className="px-3 py-2">Retrans</th><th className="px-3 py-2">Zero-Win</th><th className="px-3 py-2">Failed HS</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/60">
                    {result.tcpStats.issueStreams.map(s => (
                      <tr key={s.key} className="hover:bg-gray-800/30">
                        <td className="px-6 py-2 text-white font-mono text-xs">{linkifyIps(s.key)}</td>
                        <td className="px-3 py-2 text-gray-300">{s.rsts}</td>
                        <td className="px-3 py-2 text-gray-300">{s.retrans}</td>
                        <td className="px-3 py-2 text-gray-300">{s.zeroWin}</td>
                        <td className="px-3 py-2">{s.failedHS ? <span className="text-red-400">yes</span> : <span className="text-gray-500">no</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {tab === 'udp' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <p className="text-xs text-gray-500">Total UDP packets</p>
              <p className="text-lg font-semibold text-white mt-1">{result.udpStats.total.toLocaleString()}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <p className="text-xs text-gray-500">Total UDP bytes</p>
              <p className="text-lg font-semibold text-white mt-1">{fmtBytes(result.udpStats.totalBytes)}</p>
            </div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-800"><h2 className="text-sm font-semibold text-white">Flows ({result.udpStats.flows.length})</h2></div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                    <th className="px-6 py-2">Flow</th><th className="px-3 py-2">Packets</th><th className="px-3 py-2">Bytes</th><th className="px-3 py-2">One-sided</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60">
                  {result.udpStats.flows.map(f => (
                    <tr key={f.key} className="hover:bg-gray-800/30">
                      <td className="px-6 py-2 text-white font-mono text-xs">{linkifyIps(f.key)}</td>
                      <td className="px-3 py-2 text-gray-300">{f.pkts.toLocaleString()}</td>
                      <td className="px-3 py-2 text-gray-300">{fmtBytes(f.bytes)}</td>
                      <td className="px-3 py-2">{f.oneSided ? <span className="text-yellow-400">yes</span> : <span className="text-gray-500">no</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {tab === 'dns' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              ['Queries', result.dnsStats.total],
              ['Answered', result.dnsStats.answered],
              ['Unanswered', result.dnsStats.unanswered],
              ['Errors', result.dnsStats.errors],
            ].map(([label, value]) => (
              <div key={label as string} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <p className="text-xs text-gray-500">{label}</p>
                <p className="text-lg font-semibold text-white mt-1">{value}</p>
              </div>
            ))}
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-800"><h2 className="text-sm font-semibold text-white">Queries</h2></div>
            {result.dnsStats.queries.length === 0 ? (
              <div className="px-6 py-8 text-center text-sm text-gray-500">No DNS queries found</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
                      <th className="px-6 py-2">Query</th><th className="px-3 py-2">Answered</th><th className="px-3 py-2">RTT</th><th className="px-3 py-2">At</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/60">
                    {result.dnsStats.queries.map((q, i) => (
                      <tr key={i} className="hover:bg-gray-800/30">
                        <td className="px-6 py-2 text-white font-mono text-xs">{q.qname}</td>
                        <td className="px-3 py-2">{q.answered ? <span className="text-green-400">yes</span> : <span className="text-red-400">no</span>}</td>
                        <td className="px-3 py-2 text-gray-300">{q.rtt ? `${q.rtt} ms` : '—'}</td>
                        <td className="px-3 py-2 text-gray-500 text-xs">{safeIso(q.ts)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {tab === 'threats' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            {(['high', 'medium', 'low'] as const).map(sev => (
              <div key={sev} className={`px-3 py-1.5 rounded-lg text-xs font-medium ${SEVERITY_STYLES[sev]}`}>
                {sev}: {result.security.summary[sev]}
              </div>
            ))}
          </div>
          {result.security.threats.length === 0 ? (
            <div className="bg-gray-900 border border-gray-800 rounded-xl px-6 py-8 text-center text-sm text-gray-500">No threat indicators found</div>
          ) : result.security.threats.map((t, i) => (
            <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-1">
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_STYLES[t.severity]}`}>{t.severity}</span>
                <span className="text-xs text-gray-500">{t.category}</span>
                <p className="text-sm font-medium text-white">{t.type}</p>
              </div>
              <p className="text-sm text-gray-300 mb-2">{t.detail}</p>
              {t.evidence.length > 0 && (
                <ul className="text-xs text-gray-500 space-y-0.5 font-mono">
                  {t.evidence.map((e, j) => <li key={j}>• {linkifyIps(e)}</li>)}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
