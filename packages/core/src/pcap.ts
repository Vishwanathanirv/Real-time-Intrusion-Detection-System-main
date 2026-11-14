import { TCP, type Packet, type Proto } from "./types";

/**
 * Dependency-free libpcap reader and writer. Supports microsecond and nanosecond pcap,
 * both byte orders, and Ethernet (with 802.1Q VLAN tags), raw IPv4 and Linux "cooked" capture.
 * The streaming reader accepts arbitrary chunks, so it can parse `tcpdump -w -` output live.
 */

const LINK_ETHERNET = 1;
const LINK_RAW = 101;
const LINK_RAW_ALT = 228;
const LINK_LINUX_SLL = 113;

const ip4 = (b: Uint8Array, o: number) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;

/** Reads the first query name from a DNS message (handles compression pointers defensively). */
export function parseDnsQuery(b: Uint8Array, off: number, end: number): string | undefined {
  if (end - off < 12) return;
  const qd = (b[off + 4] << 8) | b[off + 5];
  if (qd < 1) return;
  let p = off + 12;
  const labels: string[] = [];
  for (let guard = 0; guard < 64 && p < end; guard++) {
    const len = b[p];
    if (len === 0) return labels.join(".") || undefined;
    if ((len & 0xc0) !== 0) return labels.join(".") || undefined; // pointer: not expected in questions
    if (p + 1 + len > end) return;
    let s = "";
    for (let i = 0; i < len; i++) {
      const c = b[p + 1 + i];
      s += c >= 0x21 && c <= 0x7e ? String.fromCharCode(c) : "?";
    }
    labels.push(s.toLowerCase());
    p += 1 + len;
  }
  return;
}

/** Decodes one link-layer frame into a Packet, or null for non-IPv4 traffic. */
export function decodeFrame(frame: Uint8Array, linkType: number, ts: number, wireLen: number): Packet | null {
  let o = 0;
  if (linkType === LINK_ETHERNET) {
    if (frame.length < 14) return null;
    let type = (frame[12] << 8) | frame[13];
    o = 14;
    while (type === 0x8100 || type === 0x88a8) {
      if (frame.length < o + 4) return null;
      type = (frame[o + 2] << 8) | frame[o + 3];
      o += 4;
    }
    if (type !== 0x0800) return null;
  } else if (linkType === LINK_LINUX_SLL) {
    if (frame.length < 16 || ((frame[14] << 8) | frame[15]) !== 0x0800) return null;
    o = 16;
  } else if (linkType !== LINK_RAW && linkType !== LINK_RAW_ALT) return null;

  if (frame.length < o + 20 || frame[o] >> 4 !== 4) return null;
  const ihl = (frame[o] & 0x0f) * 4;
  const totalLen = (frame[o + 2] << 8) | frame[o + 3];
  const protoNum = frame[o + 9];
  const ttl = frame[o + 8];
  const src = ip4(frame, o + 12);
  const dst = ip4(frame, o + 16);
  const l4 = o + ihl;
  const ipEnd = Math.min(frame.length, o + totalLen);
  let proto: Proto;
  let sport = 0;
  let dport = 0;
  let flags = 0;
  let payload = 0;
  let dnsQuery: string | undefined;
  if (protoNum === 6) {
    if (ipEnd < l4 + 20) return null;
    proto = "tcp";
    sport = (frame[l4] << 8) | frame[l4 + 1];
    dport = (frame[l4 + 2] << 8) | frame[l4 + 3];
    const dataOff = (frame[l4 + 12] >> 4) * 4;
    flags = frame[l4 + 13] & 0x3f;
    payload = Math.max(0, totalLen - ihl - dataOff);
  } else if (protoNum === 17) {
    if (ipEnd < l4 + 8) return null;
    proto = "udp";
    sport = (frame[l4] << 8) | frame[l4 + 1];
    dport = (frame[l4 + 2] << 8) | frame[l4 + 3];
    payload = Math.max(0, ((frame[l4 + 4] << 8) | frame[l4 + 5]) - 8);
    if (dport === 53 || sport === 53) dnsQuery = parseDnsQuery(frame, l4 + 8, ipEnd);
  } else if (protoNum === 1) {
    proto = "icmp";
    payload = Math.max(0, totalLen - ihl - 8);
  } else return null;
  return { ts, src, dst, sport, dport, proto, len: wireLen, flags, ttl, payloadLen: payload, ...(dnsQuery ? { dnsQuery } : {}) };
}

type Header = { little: boolean; nano: boolean; linkType: number };

export class PcapStreamReader {
  private buf = new Uint8Array(0);
  private header: Header | null = null;
  packets = 0;
  skipped = 0;

  constructor(private onPacket: (p: Packet) => void) {}

  push(chunk: Uint8Array): void {
    const merged = new Uint8Array(this.buf.length + chunk.length);
    merged.set(this.buf);
    merged.set(chunk, this.buf.length);
    this.buf = merged;
    let off = 0;
    const view = new DataView(this.buf.buffer, this.buf.byteOffset, this.buf.byteLength);
    if (!this.header) {
      if (this.buf.length < 24) return;
      const magic = view.getUint32(0, false);
      const table: Record<number, Omit<Header, "linkType">> = {
        0xa1b2c3d4: { little: false, nano: false },
        0xd4c3b2a1: { little: true, nano: false },
        0xa1b23c4d: { little: false, nano: true },
        0x4d3cb2a1: { little: true, nano: true },
      };
      const h = table[magic];
      if (!h) throw new Error("Not a pcap file (pcapng is not supported; convert with `editcap -F pcap`).");
      this.header = { ...h, linkType: view.getUint32(20, h.little) };
      off = 24;
    }
    const { little, nano, linkType } = this.header;
    while (this.buf.length - off >= 16) {
      const sec = view.getUint32(off, little);
      const frac = view.getUint32(off + 4, little);
      const incl = view.getUint32(off + 8, little);
      const orig = view.getUint32(off + 12, little);
      if (incl > 262_144) throw new Error("Corrupt pcap record");
      if (this.buf.length - off - 16 < incl) break;
      const ts = sec * 1000 + (nano ? frac / 1e6 : frac / 1e3);
      const p = decodeFrame(this.buf.subarray(off + 16, off + 16 + incl), linkType, ts, orig);
      if (p) {
        this.packets++;
        this.onPacket(p);
      } else this.skipped++;
      off += 16 + incl;
    }
    this.buf = this.buf.slice(off);
  }
}

export function readPcap(data: Uint8Array): { packets: Packet[]; skipped: number } {
  const packets: Packet[] = [];
  const r = new PcapStreamReader((p) => packets.push(p));
  r.push(data);
  return { packets, skipped: r.skipped };
}

// ---------- writer (used by the simulator to export realistic captures) ----------

const ipBytes = (ip: string) => ip.split(".").map(Number);

function encodeDns(name: string): number[] {
  const out = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
  for (const label of name.split(".")) {
    out.push(label.length, ...[...label].map((c) => c.charCodeAt(0)));
  }
  out.push(0, 0, 1, 0, 1);
  return out;
}

/** Builds an Ethernet/IPv4 frame for a packet. Payload bytes are zero except DNS questions. */
export function encodeFrame(p: Packet): Uint8Array {
  const dns = p.proto === "udp" && p.dnsQuery ? encodeDns(p.dnsQuery) : null;
  const l4Len = p.proto === "tcp" ? 20 : 8;
  const payload = dns ? dns.length : Math.min(p.payloadLen, 1400);
  const ipLen = 20 + l4Len + payload;
  const f = new Uint8Array(14 + ipLen);
  f.set([0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00]);
  const o = 14;
  f[o] = 0x45;
  f[o + 2] = ipLen >> 8;
  f[o + 3] = ipLen & 0xff;
  f[o + 8] = p.ttl;
  f[o + 9] = p.proto === "tcp" ? 6 : p.proto === "udp" ? 17 : 1;
  f.set(ipBytes(p.src), o + 12);
  f.set(ipBytes(p.dst), o + 16);
  const l4 = o + 20;
  if (p.proto !== "icmp") {
    f[l4] = p.sport >> 8;
    f[l4 + 1] = p.sport & 0xff;
    f[l4 + 2] = p.dport >> 8;
    f[l4 + 3] = p.dport & 0xff;
  }
  if (p.proto === "tcp") {
    f[l4 + 12] = 5 << 4;
    f[l4 + 13] = p.flags;
  } else if (p.proto === "udp") {
    const ulen = 8 + payload;
    f[l4 + 4] = ulen >> 8;
    f[l4 + 5] = ulen & 0xff;
    if (dns) f.set(dns, l4 + 8);
  } else f[l4] = 8; // echo request
  return f;
}

/** Writes a pcap. `snaplen` truncates stored bytes like `tcpdump -s`; headers are all detection needs. */
const encodedLength = (p: Packet) => 14 + 20 + (p.proto === "tcp" ? 20 : 8) + (p.proto === "udp" && p.dnsQuery ? p.dnsQuery.length + 18 : Math.min(p.payloadLen, 1400));

export function writePcap(packets: Packet[], snaplen = 65535): Uint8Array {
  const frames = packets.map((p) => {
    const f = encodeFrame(p);
    return f.length > snaplen ? f.subarray(0, snaplen) : f;
  });
  const size = 24 + frames.reduce((a, f) => a + 16 + f.length, 0);
  const out = new Uint8Array(size);
  const v = new DataView(out.buffer);
  v.setUint32(0, 0xa1b2c3d4, true);
  v.setUint16(4, 2, true);
  v.setUint16(6, 4, true);
  v.setUint32(16, snaplen, true);
  v.setUint32(20, LINK_ETHERNET, true);
  let off = 24;
  packets.forEach((p, i) => {
    const f = frames[i];
    const sec = Math.floor(p.ts / 1000);
    v.setUint32(off, sec, true);
    v.setUint32(off + 4, Math.round((p.ts - sec * 1000) * 1000), true);
    v.setUint32(off + 8, f.length, true);
    v.setUint32(off + 12, Math.max(encodedLength(p), p.len), true);
    out.set(f, off + 16);
    off += 16 + f.length;
  });
  return out;
}

export const isSynOnly = (p: Packet) => p.proto === "tcp" && (p.flags & TCP.SYN) !== 0 && (p.flags & TCP.ACK) === 0;
