"""
Server-side capture summary for the NOC widgets.

The Analyzer page parses a capture in the browser (frontend/src/lib/pcap) and
draws a protocol breakdown and a top-talkers list from it. A NOC tile has no
browser to do that in, so this module repeats the same two counts from the file
on disk. The decoding rules deliberately mirror parser.ts / analyze.ts — the
same protocol labels, the same byte accounting (captured length), the same
"top ten sources" cut — so a tile and the Analyzer agree on one capture.

Pure standard library, streamed from disk: classic pcap and pcapng, Ethernet and Linux cooked
captures, IPv4 only for talkers. Anything else is labelled the way the browser
labels it rather than guessed at.
"""
from __future__ import annotations

import struct
from collections import Counter
from pathlib import Path

_ICMP = {1: "ICMP", 6: "TCP", 17: "UDP"}


def _decode(d: bytes, link_type: int) -> tuple[str, str | None]:
    """(protocol label, source IPv4 or None) for one captured frame."""
    if link_type == 1:                                    # Ethernet
        if len(d) < 14:
            return "Unknown", None
        et = (d[12] << 8) | d[13]
        if et == 0x0800:
            return _ipv4(d, 14)
        if et == 0x0806:
            return "ARP", None
        if et == 0x86DD:
            return "IPv6", None
        if et == 0x8100:
            if len(d) < 18:
                return "VLAN", None
            return _ipv4(d, 18) if ((d[16] << 8) | d[17]) == 0x0800 else ("VLAN", None)
        return f"0x{et:04x}", None
    if link_type == 113:                                  # Linux cooked
        if len(d) < 16:
            return "Unknown", None
        et = (d[14] << 8) | d[15]
        if et == 0x0800:
            return _ipv4(d, 16)
        return ("IPv6", None) if et == 0x86DD else ("Other", None)
    return "Unknown", None


def _ipv4(d: bytes, o: int) -> tuple[str, str | None]:
    if len(d) < o + 20:
        return "IPv4", None
    src = f"{d[o + 12]}.{d[o + 13]}.{d[o + 14]}.{d[o + 15]}"
    proto = d[o + 9]
    return _ICMP.get(proto, f"IP/{proto}"), src


def _pcap(f):
    head = f.read(24)
    if len(head) < 24:
        raise ValueError("File too small for pcap")
    magic = struct.unpack_from("<I", head, 0)[0]
    le = magic == 0xA1B2C3D4
    if not le and magic != 0xD4C3B2A1:
        raise ValueError("Not a valid pcap or pcapng file")
    e = "<" if le else ">"
    link = struct.unpack_from(e + "I", head, 20)[0]
    rec = struct.Struct(e + "IIII")
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        incl = rec.unpack(h)[2]
        if incl == 0 or incl > 65535:
            return
        frame = f.read(incl)
        if len(frame) < incl:
            return
        yield frame, link


def _pcapng(f):
    # Blocks are read one at a time, so a capture of any size costs one block of
    # memory rather than the whole file.
    first = f.read(12)
    if len(first) < 12:
        raise ValueError("File too small for pcapng")
    bom = struct.unpack_from("<I", first, 8)[0]
    if bom not in (0x1A2B3C4D, 0x4D3C2B1A):
        raise ValueError("Invalid pcapng byte-order magic")
    e = "<" if bom == 0x1A2B3C4D else ">"
    blen0 = struct.unpack_from(e + "I", first, 4)[0]
    if blen0 < 12:
        raise ValueError("Corrupt pcapng header")
    f.read(blen0 - 12)                                   # rest of the section header
    links: list[int] = []
    while True:
        h = f.read(8)
        if len(h) < 8:
            return
        btype, blen = struct.unpack(e + "II", h)
        if blen < 12:
            return
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        if btype == 0x00000001:                           # interface description
            links.append(struct.unpack_from(e + "H", body, 0)[0])
        elif btype in (0x00000006, 0x00000002) and blen >= 28:   # enhanced / obsolete packet
            iface = struct.unpack_from(e + ("I" if btype == 6 else "H"), body, 0)[0]
            cap = struct.unpack_from(e + "I", body, 12)[0]
            if 0 < cap < 65536 and 20 + cap <= len(body):
                yield body[20:20 + cap], (links[iface] if iface < len(links) else 1)
        elif btype == 0x00000003 and blen >= 16:          # simple packet
            cap = min(struct.unpack_from(e + "I", body, 0)[0], blen - 16)
            if 0 < cap < 65536 and 4 + cap <= len(body):
                yield body[4:4 + cap], (links[0] if links else 1)


_cache: dict[tuple[str, int, int], dict] = {}


def summarize(path: Path) -> dict:
    """{'packets': n, 'protocols': [(label, packets)], 'talkers': [(ip, bytes)]}.

    Cached on (path, mtime, size): a capture on disk does not change, and the
    widget asks again on every refresh, so only the first look at a large
    capture pays for the parse."""
    st = path.stat()
    key = (str(path), st.st_mtime_ns, st.st_size)
    if key in _cache:
        return _cache[key]
    protocols: Counter = Counter()
    talkers: Counter = Counter()
    n = 0
    with path.open("rb") as f:
        magic = f.read(4)
        f.seek(0)
        if len(magic) < 4:
            raise ValueError("File too small")
        frames = _pcapng(f) if struct.unpack("<I", magic)[0] == 0x0A0D0D0A else _pcap(f)
        for frame, link in frames:
            label, src = _decode(frame, link)
            protocols[label] += 1
            if src:
                talkers[src] += len(frame)
            n += 1
    out = {
        "packets": n,
        "protocols": protocols.most_common(),
        "talkers": talkers.most_common(10),
    }
    if len(_cache) >= 8:
        _cache.pop(next(iter(_cache)))
    _cache[key] = out
    return out
