import { flowVector } from "./flows";
import { anomalyScore, type IForestModel } from "./iforest";
import { isSynOnly } from "./pcap";
import { MITRE, TCP, type Alert, type AlertType, type Flow, type Packet, type Severity } from "./types";

/** Tunable thresholds. Defaults follow common Suricata/Zeek-style heuristics. */
export type DetectorConfig = {
  portScan: { windowMs: number; distinctPorts: number };
  hostSweep: { windowMs: number; distinctHosts: number };
  synFlood: { windowMs: number; synPerSec: number; halfOpenRatio: number };
  bruteForce: { windowMs: number; attempts: number; ports: number[] };
  dnsTunnel: { windowMs: number; minQueries: number; entropy: number; labelLength: number };
  beacon: { minConnections: number; maxJitter: number; minIntervalMs: number };
  anomaly: { threshold: number; minBytes: number };
  dedupMs: number;
};

export const DEFAULT_CONFIG: DetectorConfig = {
  portScan: { windowMs: 15_000, distinctPorts: 25 },
  hostSweep: { windowMs: 30_000, distinctHosts: 20 },
  synFlood: { windowMs: 2_000, synPerSec: 200, halfOpenRatio: 0.85 },
  bruteForce: { windowMs: 60_000, attempts: 12, ports: [21, 22, 23, 3306, 3389, 5432, 5900] },
  dnsTunnel: { windowMs: 60_000, minQueries: 15, entropy: 3.6, labelLength: 24 },
  beacon: { minConnections: 8, maxJitter: 0.12, minIntervalMs: 2_000 },
  anomaly: { threshold: 0.7, minBytes: 2_000 },
  dedupMs: 60_000,
};

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (!s) return 0;
  const m = new Map<string, number>();
  for (const c of s) m.set(c, (m.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of m.values()) h -= (n / s.length) * Math.log2(n / s.length);
  return h;
}

/** Registered domain approximation: last two labels (three for common two-level suffixes). */
export function baseDomain(name: string): string {
  const parts = name.split(".");
  const twoLevel = /^(co|com|net|org|gov|ac|edu)\.[a-z]{2}$/.test(parts.slice(-2).join("."));
  return parts.slice(twoLevel ? -3 : -2).join(".");
}

/** Sliding window of timestamped values. */
class Window<T> {
  items: { ts: number; v: T }[] = [];
  push(ts: number, v: T, horizon: number) {
    this.items.push({ ts, v });
    const cut = ts - horizon;
    let i = 0;
    while (i < this.items.length && this.items[i].ts < cut) i++;
    if (i) this.items.splice(0, i);
  }
}

type Emit = (a: Omit<Alert, "id" | "count" | "firstSeen" | "lastSeen"> & { ts: number }) => void;

const isPrivate = (ip: string) => ip.startsWith("10.") || ip.startsWith("192.168.") || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);

export class DetectionEngine {
  readonly alerts = new Map<string, Alert>();
  private seq = 0;
  private scans = new Map<string, Window<string>>();
  private sweeps = new Map<string, Window<string>>();
  private syns = new Map<string, Window<{ src: string; done: boolean }>>();
  private auth = new Map<string, Window<number>>();
  private dns = new Map<string, Window<string>>();
  private conns = new Map<string, number[]>();
  private lastSweep = 0;

  constructor(public config: DetectorConfig = DEFAULT_CONFIG, public model: IForestModel | null = null, private onAlert: (a: Alert, isNew: boolean) => void = () => {}) {}

  private emit: Emit = (a) => {
    const key = `${a.type}|${a.src}|${a.dst}`;
    const prev = this.alerts.get(key);
    if (prev && a.ts - prev.lastSeen < this.config.dedupMs) {
      prev.count++;
      prev.lastSeen = a.ts;
      prev.evidence = { ...prev.evidence, ...a.evidence };
      if (rank(a.severity) > rank(prev.severity)) prev.severity = a.severity;
      this.onAlert(prev, false);
      return;
    }
    const alert: Alert = { id: `a${(this.seq++).toString(36)}`, type: a.type, severity: a.severity, title: a.title, description: a.description, src: a.src, dst: a.dst, mitre: a.mitre, evidence: a.evidence, count: 1, firstSeen: a.ts, lastSeen: a.ts };
    this.alerts.set(key, alert);
    this.onAlert(alert, true);
  };

  private win<T>(m: Map<string, Window<T>>, k: string): Window<T> {
    let w = m.get(k);
    if (!w) m.set(k, (w = new Window<T>()));
    return w;
  }

  private raise(type: AlertType, severity: Severity, ts: number, src: string, dst: string, title: string, description: string, evidence: Alert["evidence"]) {
    this.emit({ type, severity, ts, src, dst, title, description, mitre: MITRE[type], evidence });
  }

  /** Packet-level detectors. */
  packet(p: Packet): void {
    const c = this.config;
    if (p.proto === "tcp" && isSynOnly(p)) {
      // Vertical scan: one source probing many ports on one host.
      const w = this.win(this.scans, `${p.src}>${p.dst}`);
      w.push(p.ts, String(p.dport), c.portScan.windowMs);
      const ports = new Set(w.items.map((i) => i.v)).size;
      if (ports >= c.portScan.distinctPorts) {
        this.raise("port_scan", ports > 200 ? "high" : "medium", p.ts, p.src, p.dst, `Port scan from ${p.src}`, `${p.src} probed ${ports} different ports on ${p.dst} in ${c.portScan.windowMs / 1000}s.`, { distinctPorts: ports, windowSec: c.portScan.windowMs / 1000 });
      }
      // Horizontal sweep: one source touching many hosts on the same port.
      const s = this.win(this.sweeps, `${p.src}:${p.dport}`);
      s.push(p.ts, p.dst, c.hostSweep.windowMs);
      const hosts = new Set(s.items.map((i) => i.v)).size;
      if (hosts >= c.hostSweep.distinctHosts) {
        this.raise("host_sweep", "medium", p.ts, p.src, `*:${p.dport}`, `Host sweep on port ${p.dport}`, `${p.src} contacted ${hosts} hosts on port ${p.dport} in ${c.hostSweep.windowMs / 1000}s.`, { distinctHosts: hosts, port: p.dport });
      }
      // SYN flood: very high SYN rate to one target with handshakes left half-open.
      const f = this.win(this.syns, p.dst);
      f.push(p.ts, { src: p.src, done: false }, c.synFlood.windowMs);
      const rate = f.items.length / (c.synFlood.windowMs / 1000);
      if (rate >= c.synFlood.synPerSec) {
        const halfOpen = f.items.filter((i) => !i.v.done).length / f.items.length;
        if (halfOpen >= c.synFlood.halfOpenRatio) {
          const sources = new Set(f.items.map((i) => i.v.src)).size;
          this.raise("syn_flood", sources > 50 ? "critical" : "high", p.ts, sources > 1 ? "multiple sources" : p.src, p.dst, sources > 50 ? `Distributed SYN flood (DDoS) on ${p.dst}` : `SYN flood on ${p.dst}`, `${Math.round(rate)} SYN/s with ${Math.round(halfOpen * 100)}% of handshakes never completed, from ${sources} source address${sources > 1 ? "es" : ""}.`, { synPerSec: Math.round(rate), halfOpenPct: Math.round(halfOpen * 100), sources });
        }
      }
    } else if (p.proto === "tcp" && (p.flags & TCP.ACK) && !(p.flags & TCP.SYN)) {
      const f = this.syns.get(p.dst);
      const pending = f?.items.find((i) => !i.v.done && i.v.src === p.src);
      if (pending) pending.v.done = true;
    }

    if (p.proto === "udp" && p.dnsQuery && p.dport === 53) {
      const name = p.dnsQuery;
      const base = baseDomain(name);
      const sub = name.slice(0, Math.max(0, name.length - base.length - 1));
      const w = this.win(this.dns, `${p.src}|${base}`);
      w.push(p.ts, sub, c.dnsTunnel.windowMs);
      if (w.items.length >= c.dnsTunnel.minQueries) {
        const subs = w.items.map((i) => i.v).filter(Boolean);
        const unique = new Set(subs).size;
        const avgEntropy = subs.reduce((a, s) => a + entropy(s.replace(/\./g, "")), 0) / Math.max(1, subs.length);
        const avgLen = subs.reduce((a, s) => a + s.length, 0) / Math.max(1, subs.length);
        if (unique / w.items.length > 0.8 && avgEntropy >= c.dnsTunnel.entropy && avgLen >= c.dnsTunnel.labelLength) {
          this.raise("dns_tunnel", "high", p.ts, p.src, base, `Possible DNS tunnelling to ${base}`, `${w.items.length} queries in a minute with random-looking subdomains (${avgEntropy.toFixed(1)} bits/char, ${Math.round(avgLen)} chars). Data may be leaving through DNS.`, { queries: w.items.length, uniqueSubdomains: unique, entropy: +avgEntropy.toFixed(2), avgLength: Math.round(avgLen), example: name.slice(0, 80) });
        }
      }
    }
  }

  /** Flow-level detectors, run when a flow finishes. */
  flow(f: Flow): void {
    const c = this.config;
    if (f.proto === "tcp" && c.bruteForce.ports.includes(f.dport) && f.syn > 0) {
      const w = this.win(this.auth, `${f.src}>${f.dst}:${f.dport}`);
      w.push(f.start, f.last - f.start, c.bruteForce.windowMs);
      const short = w.items.filter((i) => i.v < 8_000).length;
      if (short >= c.bruteForce.attempts) {
        const svc = { 21: "FTP", 22: "SSH", 23: "Telnet", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC" }[f.dport] ?? `port ${f.dport}`;
        this.raise("brute_force", short > 50 ? "high" : "medium", f.last, f.src, `${f.dst}:${f.dport}`, `${svc} brute force against ${f.dst}`, `${short} short-lived ${svc} connections from ${f.src} in ${c.bruteForce.windowMs / 1000}s, typical of password guessing.`, { attempts: short, service: svc });
      }
    }

    // Beaconing: connections to the same destination at suspiciously regular intervals.
    if (f.proto === "tcp" && f.syn > 0 && !isPrivate(f.dst)) {
      const k = `${f.src}>${f.dst}:${f.dport}`;
      const starts = this.conns.get(k) ?? [];
      starts.push(f.start);
      if (starts.length > 30) starts.shift();
      this.conns.set(k, starts);
      if (starts.length >= c.beacon.minConnections) {
        const gaps = starts.slice(1).map((s, i) => s - starts[i]);
        const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
        const sd = Math.sqrt(gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length);
        const cv = sd / Math.max(1, mean);
        if (mean >= c.beacon.minIntervalMs && cv <= c.beacon.maxJitter) {
          this.raise("beaconing", "high", f.last, f.src, `${f.dst}:${f.dport}`, `Beaconing from ${f.src}`, `${starts.length} connections to ${f.dst}:${f.dport} every ${(mean / 1000).toFixed(1)}s with only ${Math.round(cv * 100)}% jitter. Malware often "phones home" like this.`, { connections: starts.length, intervalSec: +(mean / 1000).toFixed(1), jitterPct: Math.round(cv * 100) });
        }
      }
    }

    if (this.model && f.bytes >= c.anomaly.minBytes) {
      const score = anomalyScore(this.model, flowVector(f));
      if (score >= c.anomaly.threshold) {
        this.raise("anomaly", score > 0.78 ? "medium" : "low", f.last, f.src, `${f.dst}:${f.dport}`, `Unusual ${f.proto.toUpperCase()} flow from ${f.src}`, `This flow looks unlike normal traffic on the network (isolation-forest score ${score.toFixed(2)}): ${f.packets} packets, ${(f.bytes / 1024).toFixed(1)} KB, ${Math.round((f.last - f.start) / 1000)}s.`, { score: +score.toFixed(3), bytes: f.bytes, packets: f.packets, upstreamPct: Math.round((f.fwdBytes / Math.max(1, f.bytes)) * 100) });
      }
    }
  }

  /** Drops stale state; call every few seconds. */
  sweep(now: number) {
    if (now - this.lastSweep < 5_000) return;
    this.lastSweep = now;
    const prune = <T>(m: Map<string, Window<T>>, horizon: number) => {
      for (const [k, w] of m) if (!w.items.length || now - w.items[w.items.length - 1].ts > horizon) m.delete(k);
    };
    prune(this.scans, this.config.portScan.windowMs);
    prune(this.sweeps, this.config.hostSweep.windowMs);
    prune(this.syns, this.config.synFlood.windowMs);
    prune(this.auth, this.config.bruteForce.windowMs);
    prune(this.dns, this.config.dnsTunnel.windowMs);
    for (const [k, s] of this.conns) if (now - s[s.length - 1] > 10 * 60_000) this.conns.delete(k);
    for (const [k, a] of this.alerts) if (now - a.lastSeen > 6 * 60 * 60_000) this.alerts.delete(k);
  }
}

const rank = (s: Severity) => ({ low: 0, medium: 1, high: 2, critical: 3 })[s];
