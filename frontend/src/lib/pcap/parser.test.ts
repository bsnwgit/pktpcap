import { describe, it, expect } from 'vitest'
import { parsePCAP } from './parser'
import { analyzePackets } from './analyze'

// -- Minimal byte-level fixture builder --------------------------------------
// Builds real, spec-valid Ethernet/IPv4/UDP/TCP frames so the parser is
// exercised against actual bytes, not a mocked object shape.

function ipToBytes(ip: string): number[] {
  return ip.split('.').map(Number)
}

function ethHeader(etherType: number): number[] {
  return [
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // dst mac
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src mac
    (etherType >> 8) & 0xff, etherType & 0xff,
  ]
}

function ipv4Header(proto: number, srcIP: string, dstIP: string, payloadLen: number): number[] {
  const totalLen = 20 + payloadLen
  return [
    0x45, 0x00, // version/IHL, TOS
    (totalLen >> 8) & 0xff, totalLen & 0xff, // total length
    0x00, 0x00, // id
    0x00, 0x00, // flags/frag
    64, proto, // TTL, protocol
    0x00, 0x00, // checksum (unchecked by the parser)
    ...ipToBytes(srcIP),
    ...ipToBytes(dstIP),
  ]
}

function udpHeader(srcPort: number, dstPort: number, payloadLen: number): number[] {
  const len = 8 + payloadLen
  return [
    (srcPort >> 8) & 0xff, srcPort & 0xff,
    (dstPort >> 8) & 0xff, dstPort & 0xff,
    (len >> 8) & 0xff, len & 0xff,
    0x00, 0x00, // checksum
  ]
}

function dnsQuery(qname: string): number[] {
  const labels = qname.split('.').flatMap(label => [label.length, ...Array.from(label, c => c.charCodeAt(0))])
  return [
    0x12, 0x34, // id
    0x01, 0x00, // flags: standard query, recursion desired
    0x00, 0x01, // qdcount = 1
    0x00, 0x00, // ancount = 0
    0x00, 0x00, // nscount
    0x00, 0x00, // arcount
    ...labels, 0x00, // terminator
    0x00, 0x01, // qtype A
    0x00, 0x01, // qclass IN
  ]
}

function tcpSynHeader(srcPort: number, dstPort: number): number[] {
  return [
    (srcPort >> 8) & 0xff, srcPort & 0xff,
    (dstPort >> 8) & 0xff, dstPort & 0xff,
    0x00, 0x00, 0x00, 0x01, // seq num
    0x00, 0x00, 0x00, 0x00, // ack num
    0x50, 0x02, // data offset=5(*4=20), flags=SYN(0x02)
    0x20, 0x00, // window
    0x00, 0x00, // checksum
    0x00, 0x00, // urgent pointer
  ]
}

function buildClassicPcap(packets: number[][]): ArrayBuffer {
  const globalHeader = [
    0xd4, 0xc3, 0xb2, 0xa1, // magic (LE: 0xa1b2c3d4)
    0x02, 0x00, 0x04, 0x00, // version 2.4
    0x00, 0x00, 0x00, 0x00, // thiszone
    0x00, 0x00, 0x00, 0x00, // sigfigs
    0xff, 0xff, 0x00, 0x00, // snaplen
    0x01, 0x00, 0x00, 0x00, // network = 1 (Ethernet), little-endian
  ]
  const bytes: number[] = [...globalHeader]
  for (const pkt of packets) {
    const len = pkt.length
    bytes.push(
      0x00, 0x00, 0x00, 0x00, // ts_sec
      0x00, 0x00, 0x00, 0x00, // ts_usec
      len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, (len >> 24) & 0xff, // incl_len (LE)
      len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, (len >> 24) & 0xff, // orig_len
    )
    bytes.push(...pkt)
  }
  return new Uint8Array(bytes).buffer
}

describe('parsePCAP + analyzePackets', () => {
  it('parses a DNS query packet and reports it as unanswered', () => {
    const dns = dnsQuery('example.com')
    const udp = udpHeader(5000, 53, dns.length)
    const ip = ipv4Header(17, '192.168.1.10', '203.0.113.8', udp.length + dns.length)
    const eth = ethHeader(0x0800)
    const pkt = [...eth, ...ip, ...udp, ...dns]

    const buf = buildClassicPcap([pkt])
    const packets = parsePCAP(buf, 'test.pcap')

    expect(packets).toHaveLength(1)
    expect(packets[0].protocol).toBe('UDP')
    expect(packets[0].srcIP).toBe('192.168.1.10')
    expect(packets[0].dstIP).toBe('203.0.113.8')
    expect(packets[0].dns?.qname).toBe('example.com')
    expect(packets[0].dns?.isResponse).toBe(false)

    const result = analyzePackets(packets)
    expect(result).not.toBeNull()
    expect(result!.dnsStats.total).toBe(1)
    expect(result!.dnsStats.unanswered).toBe(1)
    expect(result!.metadata.totalPackets).toBe(1)
    expect(result!.protocols).toContainEqual(['UDP', 1])
  })

  it('parses a bare TCP SYN and flags a failed handshake anomaly', () => {
    const tcp = tcpSynHeader(40000, 443)
    const ip = ipv4Header(6, '10.0.0.5', '203.0.113.34', tcp.length)
    const eth = ethHeader(0x0800)
    const pkt = [...eth, ...ip, ...tcp]

    const buf = buildClassicPcap([pkt])
    const packets = parsePCAP(buf, 'test.pcap')

    expect(packets).toHaveLength(1)
    expect(packets[0].protocol).toBe('TCP')
    expect(packets[0].flags?.syn).toBe(true)
    expect(packets[0].flags?.ack).toBe(false)

    const result = analyzePackets(packets)
    expect(result).not.toBeNull()
    expect(result!.tcpStats.failedHandshakes).toBe(1)
    expect(result!.anomalies.some(a => a.type === 'Failed TCP Handshakes')).toBe(true)
  })

  it('rejects a file that is too small to be a valid pcap', () => {
    const buf = new Uint8Array([1, 2, 3, 4]).buffer
    expect(() => parsePCAP(buf, 'bad.pcap')).toThrow('File too small')
  })

  it('rejects a file with an unrecognized magic number', () => {
    const buf = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0]).buffer
    expect(() => parsePCAP(buf, 'bad.pcap')).toThrow(/Not a valid pcap/)
  })
})
