import { Rng } from "./rng";
import { TCP, type AlertType, type Packet } from "./types";

/**
 * Network traffic generator for a small office: workstations browsing, resolving DNS,
 * syncing time, using a file server and SSH. Attacks are injected on demand and every
 * generated packet carries a ground-truth label so detection can be measured.
 */

export type AttackKind = "port_scan" | "host_sweep" | "syn_flood" | "brute_force" | "dns_tunnel" | "beaconing" | "exfiltration";
export const ATTACKS: AttackKind[] = ["port_scan", "host_sweep", "syn_flood", "brute_force", "dns_tunnel", "beaconing", "exfiltration"];

/** Which alert types count as detecting each attack. */
export const EXPECTED: Record<AttackKind, AlertType[]> = {
  port_scan: ["port_scan"],
  host_sweep: ["host_sweep"],
  syn_flood: ["syn_flood"],
  brute_force: ["brute_force"],
  dns_tunnel: ["dns_tunnel"],
  beaconing: ["beaconing"],
  exfiltration: ["anomaly"],
};

export const ATTACK_LABELS: Record<AttackKind, string> = {
  port_scan: "Port scan",
  host_sweep: "Host sweep",
  syn_flood: "SYN flood (DDoS)",
  brute_force: "SSH brute force",
  dns_tunnel: "DNS tunnelling",
  beaconing: "C2 beaconing",
  exfiltration: "Data exfiltration",
};

export type LabeledPacket = Packet & { attack?: AttackKind; attackId?: string };

const SERVERS = { web: "10.0.0.10", files: "10.0.0.20", db: "10.0.0.30", dns: "10.0.0.2", gateway: "10.0.0.1" };
const INTERNET = ["142.250.183.14", "151.101.1.69", "104.16.132.229", "13.107.42.14", "52.84.150.39", "185.199.108.153", "20.205.243.166", "172.217.166.110"];
const DOMAINS = ["google.com", "github.com", "microsoft.com", "cloudflare.com", "amazonaws.com", "wikipedia.org", "linkedin.com", "npmjs.org", "slack.com", "zoom.us"];
const SUBS = ["www", "api", "mail", "cdn", "static", "login", "docs", "assets", "edge", "us-east-1"];

export class NetworkSimulator {
  readonly r: Rng;
  readonly hosts: string[];
  private port = 40_000;
  private attackSeq = 0;

  constructor(seed = 1, hostCount = 24) {
    this.r = new Rng(seed);
    this.hosts = Array.from({ length: hostCount }, (_, i) => `10.0.0.${100 + i}`);
  }

  private eph() {
    this.port = this.port >= 60_999 ? 40_000 : this.port + 1;
    return this.port;
  }

  private pkt(ts: number, src: string, dst: string, sport: number, dport: number, proto: Packet["proto"], flags: number, payloadLen: number, extra: Partial<LabeledPacket> = {}): LabeledPacket {
    const hdr = proto === "tcp" ? 54 : proto === "udp" ? 42 : 42;
    return { ts, src, dst, sport, dport, proto, flags, payloadLen, len: hdr + payloadLen, ttl: src.startsWith("10.") ? 64 : this.r.pick([52, 56, 116, 118]), ...extra };
  }

  /** A complete TCP session: handshake, data both ways, FIN teardown. */
  tcpSession(ts: number, c: string, s: string, dport: number, upBytes: number, downBytes: number, durMs: number, extra: Partial<LabeledPacket> = {}): LabeledPacket[] {
    const sp = this.eph();
    const out: LabeledPacket[] = [];
    let t = ts;
    const rtt = this.r.next() * 20 + 2;
    out.push(this.pkt(t, c, s, sp, dport, "tcp", TCP.SYN, 0, extra));
    out.push(this.pkt((t += rtt / 2), s, c, dport, sp, "tcp", TCP.SYN | TCP.ACK, 0, extra));
    out.push(this.pkt((t += rtt / 2), c, s, sp, dport, "tcp", TCP.ACK, 0, extra));
    const segs = Math.max(1, Math.ceil((upBytes + downBytes) / 1400));
    const step = Math.max(1, durMs / (segs + 1));
    let up = upBytes;
    let down = downBytes;
    for (let i = 0; i < segs && (up > 0 || down > 0); i++) {
      t += step * (0.5 + this.r.next());
      if (up > 0 && (down <= 0 || this.r.chance(upBytes / (upBytes + downBytes + 1)))) {
        const n = Math.min(1400, up);
        up -= n;
        out.push(this.pkt(t, c, s, sp, dport, "tcp", TCP.ACK | TCP.PSH, n, extra));
      } else {
        const n = Math.min(1400, down);
        down -= n;
        out.push(this.pkt(t, s, c, dport, sp, "tcp", TCP.ACK | TCP.PSH, n, extra));
      }
    }
    out.push(this.pkt((t += rtt), c, s, sp, dport, "tcp", TCP.FIN | TCP.ACK, 0, extra));
    out.push(this.pkt((t += rtt / 2), s, c, dport, sp, "tcp", TCP.FIN | TCP.ACK, 0, extra));
    out.push(this.pkt((t += rtt / 2), c, s, sp, dport, "tcp", TCP.ACK, 0, extra));
    return out;
  }

  private dnsQuery(ts: number, c: string, name: string, extra: Partial<LabeledPacket> = {}): LabeledPacket[] {
    const sp = this.eph();
    return [this.pkt(ts, c, SERVERS.dns, sp, 53, "udp", 0, 17 + name.length, { ...extra, dnsQuery: name }), this.pkt(ts + 3 + this.r.next() * 15, SERVERS.dns, c, 53, sp, "udp", 0, 60 + name.length, extra)];
  }

  /** Benign traffic for one host over `ms` starting at `ts`. */
  benign(ts: number, ms: number): LabeledPacket[] {
    const out: LabeledPacket[] = [];
    const r = this.r;
    const events = Math.max(1, Math.round((ms / 1000) * this.hosts.length * 0.6));
    for (let i = 0; i < events; i++) {
      const t = ts + r.next() * ms;
      const h = r.pick(this.hosts);
      const roll = r.next();
      if (roll < 0.45) {
        const name = `${r.pick(SUBS)}.${r.pick(DOMAINS)}`;
        out.push(...this.dnsQuery(t, h, name));
        out.push(...this.tcpSession(t + 20, h, r.pick(INTERNET), 443, r.int(400, 3000), Math.round(r.logNormal(40_000, 1.2)), r.int(80, 2500)));
      } else if (roll < 0.62) {
        out.push(...this.tcpSession(t, h, SERVERS.web, r.pick([80, 443]), r.int(300, 2000), Math.round(r.logNormal(15_000, 1)), r.int(30, 800)));
      } else if (roll < 0.74) {
        out.push(...this.tcpSession(t, h, SERVERS.files, 445, Math.round(r.logNormal(8000, 1.3)), Math.round(r.logNormal(60_000, 1.3)), r.int(200, 4000)));
      } else if (roll < 0.82) {
        out.push(...this.tcpSession(t, h, SERVERS.db, 5432, r.int(300, 4000), Math.round(r.logNormal(12_000, 1)), r.int(20, 600)));
      } else if (roll < 0.88) {
        // A legitimate admin SSH session: few connections, long-lived.
        out.push(...this.tcpSession(t, h, SERVERS.web, 22, r.int(5_000, 40_000), r.int(20_000, 200_000), r.int(20_000, 110_000)));
      } else if (roll < 0.93) {
        const sp = this.eph();
        out.push(this.pkt(t, h, SERVERS.gateway, sp, 123, "udp", 0, 48), this.pkt(t + 4, SERVERS.gateway, h, 123, sp, "udp", 0, 48));
      } else if (roll < 0.97) {
        out.push(...this.dnsQuery(t, h, `${r.pick(SUBS)}.${r.pick(DOMAINS)}`));
      } else {
        out.push(this.pkt(t, h, SERVERS.gateway, 0, 0, "icmp", 0, 56), this.pkt(t + 1, SERVERS.gateway, h, 0, 0, "icmp", 0, 56));
      }
    }
    return out;
  }

  /** Generates one attack starting at `ts`. Returns its packets and an id for scoring. */
  attack(kind: AttackKind, ts: number): { id: string; kind: AttackKind; start: number; end: number; packets: LabeledPacket[] } {
    const r = this.r;
    const id = `atk${this.attackSeq++}`;
    const tag = { attack: kind, attackId: id };
    const attacker = r.chance(0.5) ? `45.${r.int(1, 250)}.${r.int(1, 250)}.${r.int(1, 250)}` : r.pick(this.hosts);
    const out: LabeledPacket[] = [];
    let t = ts;
    switch (kind) {
      case "port_scan": {
        const target = r.pick([SERVERS.web, SERVERS.files, SERVERS.db]);
        const ports = Array.from({ length: r.int(150, 1000) }, (_, i) => i + 1).sort(() => r.next() - 0.5);
        for (const p of ports) {
          const sp = this.eph();
          out.push(this.pkt(t, attacker, target, sp, p, "tcp", TCP.SYN, 0, tag));
          out.push(this.pkt(t + 0.4, target, attacker, p, sp, "tcp", [22, 80, 443, 445, 5432].includes(p) ? TCP.SYN | TCP.ACK : TCP.RST | TCP.ACK, 0, tag));
          t += r.next() * 12;
        }
        break;
      }
      case "host_sweep": {
        const port = r.pick([22, 445, 3389]);
        for (let i = 1; i < 255; i++) {
          const sp = this.eph();
          out.push(this.pkt(t, attacker, `10.0.0.${i}`, sp, port, "tcp", TCP.SYN, 0, tag));
          t += r.next() * 60;
        }
        break;
      }
      case "syn_flood": {
        const n = r.int(3000, 6000);
        const spoofed = r.chance(0.6);
        for (let i = 0; i < n; i++) {
          const src = spoofed ? `${r.int(11, 223)}.${r.int(0, 255)}.${r.int(0, 255)}.${r.int(1, 254)}` : attacker;
          out.push(this.pkt(t, src, SERVERS.web, r.int(1024, 65535), 80, "tcp", TCP.SYN, 0, tag));
          t += r.exp(1 / 2.5);
        }
        break;
      }
      case "brute_force": {
        const target = SERVERS.web;
        for (let i = 0; i < r.int(40, 120); i++) {
          out.push(...this.tcpSession(t, attacker, target, 22, r.int(600, 1500), r.int(800, 2000), r.int(300, 2500), tag));
          t += r.int(300, 1500);
        }
        break;
      }
      case "dns_tunnel": {
        const host = r.pick(this.hosts);
        const domain = r.pick(["exfil-cdn.net", "telemetry-sync.io", "update-check.biz"]);
        const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (let i = 0; i < r.int(60, 200); i++) {
          const chunk = Array.from({ length: r.int(40, 60) }, () => r.pick([...alphabet])).join("");
          out.push(...this.dnsQuery(t, host, `${chunk.slice(0, 30)}.${chunk.slice(30)}.${domain}`, tag).map((p) => ({ ...p, src: p.src === SERVERS.dns ? p.src : host })));
          t += r.int(150, 900);
        }
        break;
      }
      case "beaconing": {
        const host = r.pick(this.hosts);
        const c2 = `185.${r.int(1, 250)}.${r.int(1, 250)}.${r.int(1, 250)}`;
        const every = r.int(4_000, 12_000);
        for (let i = 0; i < r.int(12, 20); i++) {
          out.push(...this.tcpSession(t, host, c2, 443, r.int(200, 400), r.int(300, 600), r.int(50, 200), tag));
          t += every * (1 + r.normal(0, 0.03));
        }
        break;
      }
      case "exfiltration": {
        // A workstation uploading a large archive to an unknown host on a high port.
        const host = r.pick(this.hosts);
        const dst = `91.${r.int(1, 250)}.${r.int(1, 250)}.${r.int(1, 250)}`;
        out.push(...this.tcpSession(t, host, dst, r.int(20000, 60000), r.int(4, 12) * 1_000_000, r.int(2000, 8000), r.int(40_000, 100_000), tag));
        break;
      }
    }
    out.sort((a, b) => a.ts - b.ts);
    return { id, kind, start: ts, end: out.length ? out[out.length - 1].ts : ts, packets: out };
  }
}
