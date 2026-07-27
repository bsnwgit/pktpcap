import type { Packet, DnsInfo } from './types'

export function parsePCAP(buffer: ArrayBuffer, filename: string): Packet[] {
  const dv = new DataView(buffer)
  if (buffer.byteLength < 12) throw new Error('File too small')
  const magic = dv.getUint32(0, true)
  // Route pcapng files to their own parser
  if (magic === 0x0a0d0d0a) return parsePCAPNG(buffer, filename)
  if (magic !== 0xa1b2c3d4 && magic !== 0xd4c3b2a1)
    throw new Error('Not a valid pcap or pcapng file (magic: 0x' + magic.toString(16) + ')')
  if (buffer.byteLength < 24) throw new Error('File too small for pcap')
  const le = magic === 0xa1b2c3d4
  const linkType = dv.getUint32(20, le)
  const packets: Packet[] = []
  let off = 24
  while (off + 16 <= buffer.byteLength) {
    const tsSec = dv.getUint32(off, le)
    const tsUsec = dv.getUint32(off + 4, le)
    const inclLen = dv.getUint32(off + 8, le)
    off += 16
    if (inclLen === 0 || inclLen > 65535 || off + inclLen > buffer.byteLength) break
    const raw = new Uint8Array(buffer, off, inclLen)
    const pkt = decodePacket(raw, linkType)
    pkt.timestamp = tsSec + tsUsec / 1e6
    pkt.capturedLen = inclLen
    pkt.source = filename
    packets.push(pkt)
    off += inclLen
  }
  return packets
}

export function decodePacket(d: Uint8Array, lt: number): Packet {
  if (lt === 1) return decodeEthernet(d)
  if (lt === 113) return decodeLinuxSLL(d)
  return { protocol: 'Unknown', timestamp: 0, capturedLen: 0, source: '' }
}

function decodeLinuxSLL(d: Uint8Array): Packet {
  if (d.length < 16) return { protocol: 'Unknown', timestamp: 0, capturedLen: 0, source: '' }
  const et = (d[14] << 8) | d[15]
  if (et === 0x0800) return decodeIPv4(d, 16)
  if (et === 0x86dd) return { protocol: 'IPv6', timestamp: 0, capturedLen: 0, source: '' }
  return { protocol: 'Other', timestamp: 0, capturedLen: 0, source: '' }
}

function decodeEthernet(d: Uint8Array): Packet {
  if (d.length < 14) return { protocol: 'Unknown', timestamp: 0, capturedLen: 0, source: '' }
  const et = (d[12] << 8) | d[13]
  if (et === 0x0800) return decodeIPv4(d, 14)
  if (et === 0x0806) return { protocol: 'ARP', timestamp: 0, capturedLen: 0, source: '' }
  if (et === 0x86dd) return { protocol: 'IPv6', timestamp: 0, capturedLen: 0, source: '' }
  if (et === 0x8100) {
    if (d.length < 18) return { protocol: 'VLAN', timestamp: 0, capturedLen: 0, source: '' }
    const inner = (d[16] << 8) | d[17]
    return inner === 0x0800
      ? { ...decodeIPv4(d, 18), vlan: ((d[14] << 8) | d[15]) & 0xfff }
      : { protocol: 'VLAN', timestamp: 0, capturedLen: 0, source: '' }
  }
  return { protocol: '0x' + et.toString(16).padStart(4, '0'), timestamp: 0, capturedLen: 0, source: '' }
}

function decodeIPv4(d: Uint8Array, o: number): Packet {
  const base0: Packet = { protocol: 'IPv4', timestamp: 0, capturedLen: 0, source: '' }
  if (d.length < o + 20) return base0
  const ihl = (d[o] & 0x0f) * 4
  const proto = d[o + 9]
  const sip = d[o + 12] + '.' + d[o + 13] + '.' + d[o + 14] + '.' + d[o + 15]
  const dip = d[o + 16] + '.' + d[o + 17] + '.' + d[o + 18] + '.' + d[o + 19]
  const tlen = (d[o + 2] << 8) | d[o + 3]
  const ttl = d[o + 8]
  const base = { srcIP: sip, dstIP: dip, ttl, totalLen: tlen, timestamp: 0, capturedLen: 0, source: '' }
  if (proto === 6) return { ...base, ...decodeTCP(d, o + ihl), protocol: 'TCP' }
  if (proto === 17) return { ...base, ...decodeUDP(d, o + ihl), protocol: 'UDP' }
  if (proto === 1) return { ...base, ...decodeICMP(d, o + ihl), protocol: 'ICMP' }
  return { ...base, protocol: 'IP/' + proto }
}

function decodeTCP(d: Uint8Array, o: number): Partial<Packet> {
  if (d.length < o + 20) return {}
  const sp = (d[o] << 8) | d[o + 1]
  const dp = (d[o + 2] << 8) | d[o + 3]
  const seq = ((d[o + 4] << 24) | (d[o + 5] << 16) | (d[o + 6] << 8) | d[o + 7]) >>> 0
  const ack = ((d[o + 8] << 24) | (d[o + 9] << 16) | (d[o + 10] << 8) | d[o + 11]) >>> 0
  const dataOff = (d[o + 12] >> 4) * 4
  const f = d[o + 13]
  const win = (d[o + 14] << 8) | d[o + 15]
  const ps = o + dataOff
  const pl = Math.min(d.length - ps, 512)
  const payload = pl > 0 ? d.slice(ps, ps + pl) : null
  return {
    srcPort: sp, dstPort: dp, seqNum: seq, ackNum: ack, windowSize: win,
    flags: { fin: !!(f & 1), syn: !!(f & 2), rst: !!(f & 4), psh: !!(f & 8), ack: !!(f & 16), urg: !!(f & 32) },
    payload,
  }
}

function decodeUDP(d: Uint8Array, o: number): Partial<Packet> {
  if (d.length < o + 8) return {}
  const sp = (d[o] << 8) | d[o + 1]
  const dp = (d[o + 2] << 8) | d[o + 3]
  const ps = o + 8
  const pl = Math.min(d.length - ps, 512)
  const payload = pl > 0 ? d.slice(ps, ps + pl) : null
  return { srcPort: sp, dstPort: dp, payload, dns: sp === 53 || dp === 53 ? decodeDNS(d, o + 8) : null }
}

function decodeICMP(d: Uint8Array, o: number): Partial<Packet> {
  if (d.length < o + 4) return {}
  const t = d[o]
  const c = d[o + 1]
  const n: Record<number, string> = { 0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 11: 'Time Exceeded', 12: 'Param Problem' }
  return { icmpType: t, icmpCode: c, icmpDesc: n[t] || 'Type ' + t }
}

function decodeDNS(d: Uint8Array, o: number): DnsInfo | null {
  if (d.length < o + 12) return null
  try {
    const id = (d[o] << 8) | d[o + 1]
    const flags = (d[o + 2] << 8) | d[o + 3]
    const isResp = !!(flags & 0x8000)
    const rcode = flags & 0x000f
    const an = (d[o + 6] << 8) | d[o + 7]
    let qo = o + 12
    let qname = ''
    while (qo < d.length) {
      const len = d[qo]
      if (len === 0 || (len & 0xc0) === 0xc0) break
      if (qname) qname += '.'
      for (let i = 1; i <= len && qo + i < d.length; i++) qname += String.fromCharCode(d[qo + i])
      qo += len + 1
    }
    return { id, isResponse: isResp, rcode, answers: an, qname }
  } catch {
    return null
  }
}

// ================================================================
//  PCAPNG PARSER
// ================================================================
export function parsePCAPNG(buffer: ArrayBuffer, filename: string): Packet[] {
  const dv = new DataView(buffer)
  if (buffer.byteLength < 28) throw new Error('File too small for pcapng')

  // Verify SHB block type
  const firstBlock = dv.getUint32(0, true)
  if (firstBlock !== 0x0a0d0d0a) throw new Error('Not a valid pcapng file')

  // Byte-order magic is at offset 8 inside the SHB body
  const bom = dv.getUint32(8, true)
  const le = bom === 0x1a2b3c4d
  if (bom !== 0x1a2b3c4d && bom !== 0x4d3c2b1a)
    throw new Error('Invalid pcapng byte-order magic: 0x' + bom.toString(16))

  const ifaces: Array<{ linkType: number; tsResol: number }> = []
  const packets: Packet[] = []
  let offset = 0

  while (offset + 12 <= buffer.byteLength) {
    const bType = dv.getUint32(offset, le)
    const bLen = dv.getUint32(offset + 4, le)
    if (bLen < 12 || offset + bLen > buffer.byteLength) break

    // ── Section Header Block (0x0A0D0D0A) ──────────────────────
    if (bType === 0x0a0d0d0a) {
      // nothing extra needed — interfaces already reset if this is a second SHB
    }

    // ── Interface Description Block (0x00000001) ───────────────
    else if (bType === 0x00000001) {
      const linkType = dv.getUint16(offset + 8, le)
      let tsResol = 1e6 // default: microseconds (1e6 units per second)
      // Scan options for if_tsresol (opt code 9)
      // r encodes negative exponent: resolution = base^(-r), so divisor = base^r
      let oo = offset + 16
      const bend = offset + bLen - 4
      while (oo + 4 <= bend) {
        const oType = dv.getUint16(oo, le)
        const oLen = dv.getUint16(oo + 2, le)
        if (oType === 0) break
        if (oType === 9 && oLen >= 1) {
          const r = dv.getUint8(oo + 4)
          // r & 0x80: base-2 if set, base-10 if not. r & 0x7f: the exponent.
          tsResol = r & 0x80 ? Math.pow(2, r & 0x7f) : Math.pow(10, r & 0x7f)
        }
        oo += 4 + oLen + (oLen % 4 ? 4 - (oLen % 4) : 0)
      }
      ifaces.push({ linkType, tsResol })
    }

    // ── Enhanced Packet Block (0x00000006) ─────────────────────
    else if (bType === 0x00000006 && bLen >= 28) {
      const ifaceId = dv.getUint32(offset + 8, le)
      const tsHi = dv.getUint32(offset + 12, le)
      const tsLo = dv.getUint32(offset + 16, le)
      const capLen = dv.getUint32(offset + 20, le)
      const iface = ifaces[ifaceId] || { linkType: 1, tsResol: 1e6 }
      const ts = (tsHi * 4294967296 + tsLo) / iface.tsResol
      if (capLen > 0 && capLen < 65536 && offset + 28 + capLen <= buffer.byteLength) {
        const raw = new Uint8Array(buffer, offset + 28, capLen)
        const pkt = decodePacket(raw, iface.linkType)
        pkt.timestamp = ts
        pkt.capturedLen = capLen
        pkt.source = filename
        packets.push(pkt)
      }
    }

    // ── Obsolete Packet Block (0x00000002) ─────────────────────
    else if (bType === 0x00000002 && bLen >= 28) {
      const ifaceId = dv.getUint16(offset + 8, le)
      const tsHi = dv.getUint32(offset + 12, le)
      const tsLo = dv.getUint32(offset + 16, le)
      const capLen = dv.getUint32(offset + 20, le)
      const iface = ifaces[ifaceId] || { linkType: 1, tsResol: 1e6 }
      const ts = (tsHi * 4294967296 + tsLo) / iface.tsResol
      if (capLen > 0 && capLen < 65536 && offset + 28 + capLen <= buffer.byteLength) {
        const raw = new Uint8Array(buffer, offset + 28, capLen)
        const pkt = decodePacket(raw, iface.linkType)
        pkt.timestamp = ts
        pkt.capturedLen = capLen
        pkt.source = filename
        packets.push(pkt)
      }
    }

    // ── Simple Packet Block (0x00000003) ───────────────────────
    else if (bType === 0x00000003 && bLen >= 16) {
      const origLen = dv.getUint32(offset + 8, le)
      const capLen = Math.min(origLen, bLen - 16)
      const iface = ifaces[0] || { linkType: 1, tsResol: 1e6 }
      if (capLen > 0 && capLen < 65536 && offset + 12 + capLen <= buffer.byteLength) {
        const raw = new Uint8Array(buffer, offset + 12, capLen)
        const pkt = decodePacket(raw, iface.linkType)
        pkt.timestamp = 0 // SPB has no timestamp
        pkt.capturedLen = capLen
        pkt.source = filename
        packets.push(pkt)
      }
    }

    offset += bLen
  }

  if (!packets.length) throw new Error('pcapng parsed but no packets found — file may be empty or use an unsupported block type')
  return packets
}
