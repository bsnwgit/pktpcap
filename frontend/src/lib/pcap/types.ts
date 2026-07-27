// Mechanical TypeScript port of the old Flask app's client-side pcap parser
// (service/static/index.html's parsePCAP/parsePCAPNG/decode*/analyzePackets).
// Kept 1:1 with the original structure/naming on purpose — this is a byte-
// format parser, not a place to "clean up" while porting.

export interface TcpFlags {
  fin: boolean
  syn: boolean
  rst: boolean
  psh: boolean
  ack: boolean
  urg: boolean
}

export interface DnsInfo {
  id: number
  isResponse: boolean
  rcode: number
  answers: number
  qname: string
}

export interface Packet {
  protocol: string
  srcIP?: string
  dstIP?: string
  ttl?: number
  totalLen?: number
  srcPort?: number
  dstPort?: number
  seqNum?: number
  ackNum?: number
  windowSize?: number
  flags?: TcpFlags
  payload?: Uint8Array | null
  dns?: DnsInfo | null
  icmpType?: number
  icmpCode?: number
  icmpDesc?: string
  vlan?: number
  timestamp: number
  capturedLen: number
  source: string
}

export interface PortStat {
  port: number
  proto: string
  pkts: number
  bytes: number
}

export interface ConversationStat {
  display: string
  normKey: string
  pkts: number
  bytes: number
  first: number
  last: number
  srcs: string[]
}

export interface IssueStream {
  key: string
  rsts: number
  retrans: number
  zeroWin: number
  failedHS: boolean
  pkts: number
  bytes: number
}

export interface DnsQuery {
  qname: string
  ts: number
  answered: boolean
  rcode: number | null
  rtt: string | null
}

export interface UdpFlow {
  key: string
  pkts: number
  bytes: number
  largeCount: number
  dirs: string[]
  oneSided: boolean
}

export interface Anomaly {
  severity: 'high' | 'medium' | 'low'
  type: string
  detail: string
  evidence: string[]
}

export interface Threat {
  severity: 'high' | 'medium' | 'low'
  category: string
  type: string
  detail: string
  evidence: string[]
}

export interface SecurityScanResult {
  threats: Threat[]
  summary: { total: number; high: number; medium: number; low: number }
}

export interface AnalysisResult {
  metadata: {
    totalPackets: number
    duration: string
    firstTs: string
    lastTs: string
    pps: string
    totalBytes: number
    captures: string[]
  }
  protocols: Array<[string, number]>
  topTalkers: Array<[string, number]>
  conversations: ConversationStat[]
  ports: PortStat[]
  tcpStats: {
    totalRsts: number
    failedHandshakes: number
    totalRetrans: number
    totalZeroWin: number
    issueStreams: IssueStream[]
  }
  dnsStats: {
    total: number
    answered: number
    unanswered: number
    errors: number
    queries: DnsQuery[]
  }
  anomalies: Anomaly[]
  security: SecurityScanResult
  udpStats: {
    total: number
    totalBytes: number
    flows: UdpFlow[]
    largeFlows: UdpFlow[]
    oneSided: UdpFlow[]
    highRate: UdpFlow[]
  }
  rawPackets: Packet[]
}
