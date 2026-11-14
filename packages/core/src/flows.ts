import { TCP, type Flow, type Packet } from "./types";

/**
 * Bidirectional flow table (like NetFlow/IPFIX). The initiator of a flow is whoever sent the first
 * packet. Flows end on FIN/RST, after an idle timeout, or after an active timeout for long sessions.
 */
export class FlowTable {
  private flows = new Map<string, Flow>();
  private seq = 0;
  constructor(private onClose: (f: Flow) => void, private idleMs = 30_000, private activeMs = 120_000) {}

  get active() {
    return this.flows.size;
  }

  private key(p: Packet, reverse = false) {
    return reverse ? `${p.proto}|${p.dst}:${p.dport}|${p.src}:${p.sport}` : `${p.proto}|${p.src}:${p.sport}|${p.dst}:${p.dport}`;
  }

  add(p: Packet): Flow {
    let f = this.flows.get(this.key(p));
    let forward = true;
    if (!f) {
      f = this.flows.get(this.key(p, true));
      forward = !f;
    }
    if (!f) {
      f = {
        id: `f${(this.seq++).toString(36)}`,
        src: p.src,
        dst: p.dst,
        sport: p.sport,
        dport: p.dport,
        proto: p.proto,
        start: p.ts,
        last: p.ts,
        packets: 0,
        bytes: 0,
        fwdPackets: 0,
        bwdPackets: 0,
        fwdBytes: 0,
        bwdBytes: 0,
        syn: 0,
        synAck: 0,
        ack: 0,
        rst: 0,
        fin: 0,
        established: false,
      };
      this.flows.set(this.key(p), f);
      forward = true;
    }
    f.last = Math.max(f.last, p.ts);
    f.packets++;
    f.bytes += p.len;
    if (forward) {
      f.fwdPackets++;
      f.fwdBytes += p.len;
    } else {
      f.bwdPackets++;
      f.bwdBytes += p.len;
    }
    if (p.proto === "tcp") {
      const syn = (p.flags & TCP.SYN) !== 0;
      const ack = (p.flags & TCP.ACK) !== 0;
      if (syn && !ack) f.syn++;
      if (syn && ack) f.synAck++;
      if (ack && !syn) {
        f.ack++;
        if (f.synAck > 0 && forward) f.established = true;
      }
      if (p.flags & TCP.RST) f.rst++;
      if (p.flags & TCP.FIN) f.fin++;
      if (p.flags & TCP.RST || f.fin >= 2) this.close(f);
    }
    return f;
  }

  private close(f: Flow) {
    for (const [k, v] of this.flows) if (v === f) this.flows.delete(k);
    this.onClose(f);
  }

  /** Expires idle and long-running flows; call periodically with the current time. */
  sweep(now: number) {
    for (const [k, f] of this.flows) {
      if (now - f.last > this.idleMs || now - f.start > this.activeMs) {
        this.flows.delete(k);
        this.onClose(f);
      }
    }
  }

  flush() {
    for (const [k, f] of this.flows) {
      this.flows.delete(k);
      this.onClose(f);
    }
  }
}

/** Numeric features of a finished flow for the anomaly model. */
export const FLOW_FEATURES = ["log_bytes", "log_packets", "log_duration_ms", "bytes_per_packet", "fwd_ratio", "syn_ratio", "rst_ratio", "is_established", "dport_class", "is_udp"] as const;

export function flowVector(f: Flow): number[] {
  const dur = Math.max(0, f.last - f.start);
  const well = [22, 25, 53, 80, 123, 443, 445, 3389, 993, 587];
  return [
    Math.log1p(f.bytes),
    Math.log1p(f.packets),
    Math.log1p(dur),
    f.bytes / Math.max(1, f.packets),
    f.fwdBytes / Math.max(1, f.bytes),
    f.syn / Math.max(1, f.packets),
    f.rst / Math.max(1, f.packets),
    f.established ? 1 : 0,
    well.includes(f.dport) ? 0 : f.dport < 1024 ? 1 : f.dport < 49152 ? 2 : 3,
    f.proto === "udp" ? 1 : 0,
  ];
}
