import type {
  Packet, AnalysisResult, PortStat, ConversationStat, IssueStream, DnsQuery, UdpFlow,
  Anomaly, SecurityScanResult, Threat,
} from './types'

export function safeIso(ts: number): string {
  try {
    if (!isFinite(ts) || ts < 0 || ts > 4e9) return 'N/A'
    return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 23)
  } catch {
    return 'N/A'
  }
}

export function fmtBytes(b: number): string {
  if (b < 1024) return b + ' B'
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'
  return (b / 1048576).toFixed(2) + ' MB'
}

export function analyzePackets(pkts: Packet[]): AnalysisResult | null {
  if (!pkts.length) return null
  pkts.sort((a, b) => a.timestamp - b.timestamp)
  const first = pkts[0].timestamp
  const last = pkts[pkts.length - 1].timestamp
  const dur = last - first

  const protocols: Record<string, number> = {}
  const talkers: Record<string, number> = {}
  const convMap: Record<string, { display: string; normKey: string; pkts: number; bytes: number; first: number; last: number; srcs: Set<string> }> = {}
  const tcpStreams: Record<string, { syns: number; synAcks: number; rsts: number; fins: number; zeroWin: number; retrans: number; pkts: number; bytes: number; seqs: Record<string, Set<number>> }> = {}
  const udpFlows: Record<string, { key: string; pkts: number; bytes: number; largeCount: number; dirs: Set<string> }> = {}
  const dnsMap: Record<number, { qname: string; ts: number; answered: boolean; rcode: number | null; rtt: string | null }> = {}
  const portMap: Record<string, PortStat> = {}
  let totalBytes = 0

  for (const p of pkts) {
    protocols[p.protocol] = (protocols[p.protocol] || 0) + 1
    totalBytes += p.capturedLen

    // Port tracking — count both src and dst, keyed as "PROTO/port"
    if ((p.protocol === 'TCP' || p.protocol === 'UDP') && p.srcPort && p.dstPort) {
      // Only count the lower-numbered port (usually the service port) to avoid double-counting
      const svc = Math.min(p.srcPort, p.dstPort)
      const key = p.protocol + '/' + svc
      if (!portMap[key]) portMap[key] = { port: svc, proto: p.protocol, pkts: 0, bytes: 0 }
      portMap[key].pkts++
      portMap[key].bytes += p.capturedLen
    }

    if (p.srcIP) talkers[p.srcIP] = (talkers[p.srcIP] || 0) + p.capturedLen

    if (p.srcIP && p.dstIP) {
      const normKey = [p.srcIP + (p.srcPort || ''), p.dstIP + (p.dstPort || '')].sort().join('|') + '|' + p.protocol
      const display = p.srcPort && p.dstPort
        ? `${p.srcIP}:${p.srcPort} ↔ ${p.dstIP}:${p.dstPort} [${p.protocol}]`
        : `${p.srcIP} ↔ ${p.dstIP} [${p.protocol}]`
      if (!convMap[normKey]) convMap[normKey] = { display, normKey, pkts: 0, bytes: 0, first: p.timestamp, last: p.timestamp, srcs: new Set() }
      const c = convMap[normKey]
      c.pkts++
      c.bytes += p.capturedLen
      c.last = p.timestamp
      c.srcs.add(p.source)
    }

    if (p.protocol === 'TCP' && p.srcIP && p.flags) {
      const nk = [p.srcIP + ':' + (p.srcPort || '?'), p.dstIP + ':' + (p.dstPort || '?')].sort().join(' ↔ ')
      if (!tcpStreams[nk]) tcpStreams[nk] = { syns: 0, synAcks: 0, rsts: 0, fins: 0, zeroWin: 0, retrans: 0, pkts: 0, bytes: 0, seqs: {} }
      const s = tcpStreams[nk]
      s.pkts++
      s.bytes += p.capturedLen
      if (p.flags.syn && !p.flags.ack) s.syns++
      if (p.flags.syn && p.flags.ack) s.synAcks++
      if (p.flags.rst) s.rsts++
      if (p.flags.fin) s.fins++
      if (p.windowSize === 0 && !p.flags.syn && !p.flags.rst) s.zeroWin++
      if (p.seqNum !== undefined) {
        const sk = p.srcIP + ':' + p.srcPort
        if (!s.seqs[sk]) s.seqs[sk] = new Set()
        if (s.seqs[sk].has(p.seqNum) && p.seqNum !== 0) {
          s.retrans++
        } else {
          s.seqs[sk].add(p.seqNum)
          if (s.seqs[sk].size > 1500) {
            const v = s.seqs[sk].values().next().value
            if (v !== undefined) s.seqs[sk].delete(v)
          }
        }
      }
    }

    if (p.dns) {
      const { id, isResponse, qname, rcode } = p.dns
      if (!isResponse) {
        dnsMap[id] = { qname: qname || '(unknown)', ts: p.timestamp, answered: false, rcode: null, rtt: null }
      } else if (dnsMap[id] && !dnsMap[id].answered) {
        dnsMap[id].answered = true
        dnsMap[id].rcode = rcode
        dnsMap[id].rtt = ((p.timestamp - dnsMap[id].ts) * 1000).toFixed(1)
      }
    }

    if (p.protocol === 'UDP' && p.srcIP && p.dstIP && p.srcPort && p.dstPort) {
      const nk = [p.srcIP + ':' + p.srcPort, p.dstIP + ':' + p.dstPort].sort().join(' ↔ ')
      if (!udpFlows[nk]) udpFlows[nk] = { key: nk, pkts: 0, bytes: 0, largeCount: 0, dirs: new Set() }
      const f = udpFlows[nk]
      f.pkts++
      f.bytes += p.capturedLen
      if (p.capturedLen > 1400) f.largeCount++
      // track directionality for one-sided detection
      f.dirs.add(p.srcIP + ':' + p.srcPort)
    }
  }

  // TCP aggregates
  let totalRsts = 0
  let totalRetrans = 0
  let totalZeroWin = 0
  let failedHS = 0
  const issueStreams: IssueStream[] = []
  for (const [k, s] of Object.entries(tcpStreams)) {
    totalRsts += s.rsts
    totalRetrans += s.retrans
    totalZeroWin += s.zeroWin
    if (s.syns > 0 && s.synAcks === 0) failedHS++
    if (s.rsts > 2 || s.retrans > 5 || s.zeroWin > 2 || (s.syns > 0 && s.synAcks === 0))
      issueStreams.push({ key: k, rsts: s.rsts, retrans: s.retrans, zeroWin: s.zeroWin, failedHS: s.syns > 0 && s.synAcks === 0, pkts: s.pkts, bytes: s.bytes })
  }

  // DNS aggregates
  const dnsAll: DnsQuery[] = Object.values(dnsMap)
  const dnsUnanswered = dnsAll.filter(d => !d.answered)
  const dnsErrors = dnsAll.filter(d => d.answered && d.rcode !== 0)

  // UDP aggregates
  const udpFlowArr: UdpFlow[] = Object.values(udpFlows).map(f => ({ ...f, dirs: [...f.dirs], oneSided: f.dirs.size === 1 }))
  udpFlowArr.sort((a, b) => b.pkts - a.pkts)
  const udpTotal = udpFlowArr.reduce((s, f) => s + f.pkts, 0)
  const udpBytes = udpFlowArr.reduce((s, f) => s + f.bytes, 0)
  const udpLargeFlows = udpFlowArr.filter(f => f.largeCount > 0)
  const udpOneSided = udpFlowArr.filter(f => f.oneSided)
  const udpHighRate = udpFlowArr.filter(f => f.pkts > 200)

  // Anomalies
  const anomalies: Anomaly[] = []
  const ICMP_TYPE_NAMES: Record<number, string> = { 3: 'Unreachable', 4: 'Source Quench', 5: 'Redirect', 11: 'Time Exceeded', 12: 'Parameter Problem' }
  const DNS_RCODES = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED']
  if (failedHS > 0) anomalies.push({
    severity: 'high', type: 'Failed TCP Handshakes',
    detail: `${failedHS} connection(s) have SYN with no SYN-ACK — possible firewall block, routing blackhole, or host unreachable`,
    evidence: issueStreams.filter(s => s.failedHS).slice(0, 10).map(s => `Stream: ${s.key} — SYN sent, no SYN-ACK received`),
  })
  if (totalRsts > 10) anomalies.push({
    severity: 'high', type: 'High TCP RST Rate',
    detail: `${totalRsts} RST packets — abrupt connection terminations across multiple streams`,
    evidence: issueStreams.filter(s => s.rsts > 0).sort((a, b) => b.rsts - a.rsts).slice(0, 10).map(s => `Stream: ${s.key} — ${s.rsts} RST(s)`),
  })
  else if (totalRsts > 3) anomalies.push({
    severity: 'medium', type: 'TCP RSTs Detected',
    detail: `${totalRsts} RST packets — connection refusals or mid-session terminations`,
    evidence: issueStreams.filter(s => s.rsts > 0).sort((a, b) => b.rsts - a.rsts).slice(0, 10).map(s => `Stream: ${s.key} — ${s.rsts} RST(s)`),
  })
  if (totalRetrans > 20) anomalies.push({
    severity: 'high', type: 'Excessive Retransmissions',
    detail: `${totalRetrans} retransmissions — significant packet loss on the path`,
    evidence: issueStreams.filter(s => s.retrans > 0).sort((a, b) => b.retrans - a.retrans).slice(0, 10).map(s => `Stream: ${s.key} — ${s.retrans} retransmission(s)`),
  })
  else if (totalRetrans > 5) anomalies.push({
    severity: 'medium', type: 'TCP Retransmissions',
    detail: `${totalRetrans} retransmissions — some loss present`,
    evidence: issueStreams.filter(s => s.retrans > 0).sort((a, b) => b.retrans - a.retrans).slice(0, 10).map(s => `Stream: ${s.key} — ${s.retrans} retransmission(s)`),
  })
  if (totalZeroWin > 5) anomalies.push({
    severity: 'medium', type: 'TCP Zero Window',
    detail: `${totalZeroWin} zero-window ads — receiver buffer exhaustion, slow application or overloaded host`,
    evidence: issueStreams.filter(s => s.zeroWin > 0).sort((a, b) => b.zeroWin - a.zeroWin).slice(0, 10).map(s => `Stream: ${s.key} — ${s.zeroWin} zero-window ad(s)`),
  })
  if (dnsUnanswered.length > 3) anomalies.push({
    severity: 'high', type: 'Unanswered DNS Queries',
    detail: `${dnsUnanswered.length} DNS queries with no response — DNS server unreachable or dropping queries`,
    evidence: dnsUnanswered.slice(0, 10).map(d => `Query: ${d.qname} (at ${safeIso(d.ts)})`),
  })
  else if (dnsUnanswered.length > 0) anomalies.push({
    severity: 'medium', type: 'DNS Queries Unanswered',
    detail: `${dnsUnanswered.length} DNS queries received no response`,
    evidence: dnsUnanswered.slice(0, 10).map(d => `Query: ${d.qname} (at ${safeIso(d.ts)})`),
  })
  if (dnsErrors.length > 0) anomalies.push({
    severity: 'medium', type: 'DNS Resolution Errors',
    detail: `${dnsErrors.length} DNS error responses (NXDOMAIN, SERVFAIL, REFUSED, etc.)`,
    evidence: dnsErrors.slice(0, 10).map(d => `${d.qname} → ${DNS_RCODES[d.rcode as number] || 'rcode:' + d.rcode}`),
  })
  const icmpErrs = pkts.filter(p => p.protocol === 'ICMP' && p.icmpType !== 0 && p.icmpType !== 8)
  if (icmpErrs.length > 0) anomalies.push({
    severity: 'medium', type: 'ICMP Error Messages',
    detail: `${icmpErrs.length} ICMP errors (Unreachable, Time Exceeded, etc.)`,
    evidence: icmpErrs.slice(0, 10).map(p => `${p.srcIP} → ${p.dstIP}: ${ICMP_TYPE_NAMES[p.icmpType as number] || 'type ' + p.icmpType} (${safeIso(p.timestamp)})`),
  })

  const captures = [...new Set(pkts.map(p => p.source))]
  const convs: ConversationStat[] = Object.entries(convMap).sort((a, b) => b[1].pkts - a[1].pkts).slice(0, 60)
    .map(([, v]) => ({ ...v, srcs: [...v.srcs] }))

  const ports = Object.values(portMap).sort((a, b) => b.pkts - a.pkts).slice(0, 30)
  const security = securityScan(pkts)

  return {
    metadata: {
      totalPackets: pkts.length, duration: dur.toFixed(3),
      firstTs: safeIso(first),
      lastTs: safeIso(last),
      pps: dur > 0 ? (pkts.length / dur).toFixed(1) : 'N/A', totalBytes, captures,
    },
    protocols: Object.entries(protocols).sort((a, b) => b[1] - a[1]),
    topTalkers: Object.entries(talkers).sort((a, b) => b[1] - a[1]).slice(0, 10),
    conversations: convs,
    ports,
    tcpStats: {
      totalRsts, failedHandshakes: failedHS, totalRetrans, totalZeroWin,
      issueStreams: issueStreams.slice(0, 12),
    },
    dnsStats: {
      total: dnsAll.length, answered: dnsAll.filter(d => d.answered).length,
      unanswered: dnsUnanswered.length, errors: dnsErrors.length,
      queries: dnsAll.slice(0, 30),
    },
    anomalies,
    security,
    udpStats: {
      total: udpTotal, totalBytes: udpBytes, flows: udpFlowArr.slice(0, 40),
      largeFlows: udpLargeFlows.slice(0, 20), oneSided: udpOneSided.slice(0, 20),
      highRate: udpHighRate.slice(0, 10),
    },
    rawPackets: pkts,
  }
}

// ================================================================
//  SECURITY SCAN ENGINE
// ================================================================
function isPrivate(ip: string): boolean {
  const [a, b] = ip.split('.').map(Number)
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}

export function securityScan(pkts: Packet[]): SecurityScanResult {
  const KNOWN_DNS = new Set(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '208.67.222.222', '208.67.220.220'])  // sanitize: allow-public-ip
  const CLEARTEXT: Record<number, string> = { 21: 'FTP', 23: 'Telnet', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 25: 'SMTP', 119: 'NNTP', 194: 'IRC', 69: 'TFTP', 512: 'rexec', 513: 'rlogin', 514: 'rsh' }
  const BRUTE_PORTS = new Set([22, 23, 3389, 21, 25, 110, 143, 389, 3306, 5432, 1433, 5900])
  const ADMIN_PORTS = new Set([22, 445, 3389, 135, 139, 5985, 5986, 5900, 3306, 5432, 1433])
  const PORT_NAMES: Record<number, string> = { 22: 'SSH', 23: 'Telnet', 3389: 'RDP', 21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 389: 'LDAP', 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 5985: 'WinRM', 445: 'SMB', 135: 'RPC', 139: 'NetBIOS', 5900: 'VNC' }

  const srcTargets: Record<string, { hosts: Set<string>; ports: Set<number>; pairs: Set<string> }> = {}
  const cleartext: Record<number, number> = {}
  const cleartextIPs: Record<number, Set<string>> = {}
  const bruteMap: Record<string, number> = {}
  const bruteTargets: Record<string, Set<string>> = {}
  const extTransfers: Record<string, number> = {}
  const lateralMap: Record<string, { srcIP: string; port: number; targets: Set<string> }> = {}
  const dnsPerSrc: Record<string, { count: number; longNames: string[] }> = {}
  const dnsServers = new Set<string>()

  for (const p of pkts) {
    if (!p.srcIP || !p.dstIP) continue
    const sPriv = isPrivate(p.srcIP)
    const dPriv = isPrivate(p.dstIP)

    // Port scan: track unique dst host:port per src
    if ((p.protocol === 'TCP' || p.protocol === 'UDP') && p.dstPort) {
      if (!srcTargets[p.srcIP]) srcTargets[p.srcIP] = { hosts: new Set(), ports: new Set(), pairs: new Set() }
      srcTargets[p.srcIP].hosts.add(p.dstIP)
      srcTargets[p.srcIP].ports.add(p.dstPort)
      srcTargets[p.srcIP].pairs.add(p.dstIP + ':' + p.dstPort)
    }

    // Cleartext — count by service port (either direction)
    if (p.protocol === 'TCP') {
      const svcPort = p.dstPort && CLEARTEXT[p.dstPort] ? p.dstPort : p.srcPort && CLEARTEXT[p.srcPort] ? p.srcPort : null
      if (svcPort) {
        cleartext[svcPort] = (cleartext[svcPort] || 0) + 1
        if (!cleartextIPs[svcPort]) cleartextIPs[svcPort] = new Set()
        cleartextIPs[svcPort].add(p.srcIP + ' → ' + p.dstIP)
      }
    }

    // Brute force: SYNs to sensitive ports
    if (p.protocol === 'TCP' && p.flags?.syn && !p.flags?.ack && p.dstPort && BRUTE_PORTS.has(p.dstPort)) {
      const k = p.srcIP + '|' + p.dstPort
      bruteMap[k] = (bruteMap[k] || 0) + 1
      if (!bruteTargets[k]) bruteTargets[k] = new Set()
      bruteTargets[k].add(p.dstIP)
    }

    // Large outbound to external
    if (sPriv && !dPriv) {
      const k = p.srcIP + '→' + p.dstIP
      extTransfers[k] = (extTransfers[k] || 0) + p.capturedLen
    }

    // Lateral movement: internal→internal on admin ports
    if (sPriv && dPriv && p.protocol === 'TCP' && p.dstPort && ADMIN_PORTS.has(p.dstPort)) {
      const k = p.srcIP + '|' + p.dstPort
      if (!lateralMap[k]) lateralMap[k] = { srcIP: p.srcIP, port: p.dstPort, targets: new Set() }
      lateralMap[k].targets.add(p.dstIP)
    }

    // DNS analysis
    if (p.dns && !p.dns.isResponse) {
      if (!dnsPerSrc[p.srcIP]) dnsPerSrc[p.srcIP] = { count: 0, longNames: [] }
      dnsPerSrc[p.srcIP].count++
      if (p.dns.qname && p.dns.qname.length > 50) dnsPerSrc[p.srcIP].longNames.push(p.dns.qname)
      if (p.dstIP) dnsServers.add(p.dstIP)
    }
  }

  const threats: Threat[] = []

  // Port scan
  for (const [srcIP, t] of Object.entries(srcTargets)) {
    if (t.pairs.size > 50 && t.ports.size > 20)
      threats.push({
        severity: 'high', category: 'Reconnaissance', type: 'Port Scan',
        detail: `${srcIP} hit ${t.pairs.size} unique host:port pairs across ${t.hosts.size} hosts / ${t.ports.size} ports`,
        evidence: [`Source: ${srcIP}`, `Hosts targeted: ${[...t.hosts].slice(0, 5).join(', ')}${t.hosts.size > 5 ? ' …and ' + (t.hosts.size - 5) + ' more' : ''}`,
          `Sample targets: ${[...t.pairs].slice(0, 8).join(', ')}${t.pairs.size > 8 ? ' …' : ''}`,
          `Distinct ports: ${[...t.ports].slice(0, 10).sort((a, b) => a - b).join(', ')}${t.ports.size > 10 ? ' …' : ''}`],
      })
    else if (t.pairs.size > 20 && t.ports.size > 10)
      threats.push({
        severity: 'medium', category: 'Reconnaissance', type: 'Possible Port Scan',
        detail: `${srcIP} hit ${t.pairs.size} unique host:port combos — possible scan`,
        evidence: [`Source: ${srcIP}`, `Sample targets: ${[...t.pairs].slice(0, 8).join(', ')}`,
          `Distinct ports seen: ${[...t.ports].slice(0, 10).sort((a, b) => a - b).join(', ')}`],
      })
  }

  // Cleartext
  for (const [portStr, count] of Object.entries(cleartext)) {
    const port = Number(portStr)
    if (count > 0) {
      const sev = [23, 512, 513, 514].includes(port) ? 'high' : 'medium'
      threats.push({
        severity: sev, category: 'Credential Risk', type: `Cleartext ${CLEARTEXT[port]}`,
        detail: `${count} packets on port ${port} (${CLEARTEXT[port]}) — credentials/data in plaintext`,
        evidence: [`Protocol: ${CLEARTEXT[port]} (port ${port})`, `Packet count: ${count}`,
          ...[...(cleartextIPs[port] || [])].slice(0, 8).map(f => `Flow: ${f}`)],
      })
    }
  }

  // Brute force
  for (const [key, count] of Object.entries(bruteMap)) {
    if (count > 15) {
      const [srcIP, dstPortStr] = key.split('|')
      const dstPort = Number(dstPortStr)
      const tgts = [...(bruteTargets[key] || [])]
      threats.push({
        severity: 'high', category: 'Brute Force', type: `Brute Force — ${PORT_NAMES[dstPort] || 'port ' + dstPort}`,
        detail: `${srcIP} sent ${count} SYN packets to port ${dstPort} (${PORT_NAMES[dstPort] || ''}) — credential spray or brute force`,
        evidence: [`Attacker: ${srcIP}`, `Target port: ${dstPort} (${PORT_NAMES[dstPort] || 'unknown service'})`,
          `SYN count: ${count}`, `Target host(s): ${tgts.slice(0, 5).join(', ')}${tgts.length > 5 ? ' …and ' + (tgts.length - 5) + ' more' : ''}`],
      })
    }
  }

  // Large outbound
  const extSorted = Object.entries(extTransfers).sort((a, b) => b[1] - a[1]).slice(0, 5)
  for (const [flow, bytes] of extSorted) {
    if (bytes > 1048576) {
      const [src, dst] = flow.split('→')
      threats.push({
        severity: bytes > 10485760 ? 'high' : 'medium', category: 'Data Transfer', type: 'Large Outbound Transfer',
        detail: `${flow} — ${fmtBytes(bytes)} sent to external host — possible exfiltration or bulk upload`,
        evidence: [`Source (internal): ${src}`, `Destination (external): ${dst}`, `Volume transferred: ${fmtBytes(bytes)}`,
          `Threshold: ${bytes > 10485760 ? 'HIGH (>10 MB)' : 'MEDIUM (>1 MB)'}`],
      })
    }
  }

  // Lateral movement
  for (const [, s] of Object.entries(lateralMap)) {
    if (s.targets.size >= 3) {
      const tgts = [...s.targets]
      threats.push({
        severity: 'high', category: 'Lateral Movement', type: `Admin Port Spread (${PORT_NAMES[s.port] || 'port ' + s.port})`,
        detail: `${s.srcIP} connected to ${s.targets.size} internal hosts on port ${s.port} (${PORT_NAMES[s.port] || ''}) — possible lateral movement`,
        evidence: [`Source: ${s.srcIP}`, `Admin port: ${s.port} (${PORT_NAMES[s.port] || 'unknown'})`,
          `Target hosts (${tgts.length}): ${tgts.slice(0, 8).join(', ')}${tgts.length > 8 ? ' …' : ''}`],
      })
    }
  }

  // DNS tunneling
  for (const [srcIP, stats] of Object.entries(dnsPerSrc)) {
    if (stats.longNames.length > 2)
      threats.push({
        severity: 'medium', category: 'Covert Channel', type: 'DNS Tunneling Indicator',
        detail: `${srcIP}: ${stats.longNames.length} queries with names >50 chars — e.g. "${stats.longNames[0].slice(0, 55)}…"`,
        evidence: [`Source: ${srcIP}`, `Long-name query count: ${stats.longNames.length}`,
          ...stats.longNames.slice(0, 6).map(n => `Query: ${n}`)],
      })
    else if (stats.count > 100)
      threats.push({
        severity: 'medium', category: 'Covert Channel', type: 'High DNS Query Rate',
        detail: `${srcIP} issued ${stats.count} DNS queries — possible tunneling or misconfiguration`,
        evidence: [`Source: ${srcIP}`, `Total DNS queries: ${stats.count}`],
      })
  }

  // Non-standard DNS servers
  const suspectDNS = [...dnsServers].filter(ip => !KNOWN_DNS.has(ip) && !ip.endsWith('.1') && !ip.endsWith('.2') && !ip.endsWith('.254'))
  if (suspectDNS.length > 0)
    threats.push({
      severity: 'low', category: 'DNS', type: 'Non-Standard DNS Resolvers',
      detail: `Queries sent to: ${suspectDNS.slice(0, 5).join(', ')} — verify these are authorized DNS servers`,
      evidence: [`Non-standard resolvers observed:`, ...suspectDNS.slice(0, 10).map(ip => `  ${ip}`),
        `Known-good DNS servers: 8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9`],  // sanitize: allow-public-ip
    })

  threats.sort((a, b) => ({ high: 0, medium: 1, low: 2 }[a.severity] - { high: 0, medium: 1, low: 2 }[b.severity]))
  return {
    threats,
    summary: {
      total: threats.length,
      high: threats.filter(t => t.severity === 'high').length,
      medium: threats.filter(t => t.severity === 'medium').length,
      low: threats.filter(t => t.severity === 'low').length,
    },
  }
}
