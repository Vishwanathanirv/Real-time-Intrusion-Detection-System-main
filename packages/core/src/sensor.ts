import { DEFAULT_CONFIG, DetectionEngine, type BaselineModel, type DetectorConfig } from "./detectors";
import { DEFAULT_RULES } from "./default-rules";
import { compileRules } from "./rules";
import { FlowTable, flowVector } from "./flows";
import { trainIForest } from "./iforest";
import { describeJa4 } from "./tls";
import { NetworkSimulator } from "./simulator";
import type { Alert, Flow, Packet } from "./types";

export type TrafficStats = {
  packets: number;
  bytes: number;
  flows: number;
  activeFlows: number;
  protocols: Record<string, number>;
  topTalkers: { ip: string; bytes: number; packets: number }[];
  topPorts: { port: number; packets: number }[];
  /** Per-second series for the last 120 seconds. */
  series: { t: number; packets: number; bytes: number; alerts: number }[];
};

/**
 * Wires packet decoding output into the flow table and detectors, and keeps
 * lightweight traffic statistics for the dashboard.
 */
export class Sensor {
  readonly flows: FlowTable;
  readonly engine: DetectionEngine;
  private totals = { packets: 0, bytes: 0, flows: 0 };
  private protocols: Record<string, number> = { tcp: 0, udp: 0, icmp: 0 };
  private talkers = new Map<string, { bytes: number; packets: number }>();
  private ports = new Map<number, number>();
  private series = new Map<number, { packets: number; bytes: number; alerts: number }>();
  processingNs = 0;

  constructor(opts: { config?: DetectorConfig; model?: BaselineModel | null; rules?: string | null; onAlert?: (a: Alert, isNew: boolean) => void; onFlow?: (f: Flow) => void } = {}) {
    this.engine = new DetectionEngine(opts.config ?? DEFAULT_CONFIG, opts.model ?? null, (a, isNew) => {
      this.bucket(a.lastSeen).alerts += isNew ? 1 : 0;
      opts.onAlert?.(a, isNew);
    });
    if (opts.rules !== null) this.engine.setRules(compileRules(opts.rules ?? DEFAULT_RULES).rules);
    this.flows = new FlowTable((f) => {
      this.totals.flows++;
      this.engine.flow(f);
      opts.onFlow?.(f);
    });
  }

  private bucket(ts: number) {
    const s = Math.floor(ts / 1000);
    let b = this.series.get(s);
    if (!b) {
      b = { packets: 0, bytes: 0, alerts: 0 };
      this.series.set(s, b);
      for (const k of this.series.keys()) if (k < s - 180) this.series.delete(k);
    }
    return b;
  }

  ingest(p: Packet): void {
    const t0 = performance.now();
    this.totals.packets++;
    this.totals.bytes += p.len;
    this.protocols[p.proto]++;
    const tk = this.talkers.get(p.src) ?? { bytes: 0, packets: 0 };
    tk.bytes += p.len;
    tk.packets++;
    this.talkers.set(p.src, tk);
    if (p.dport && p.dport < 49152) this.ports.set(p.dport, (this.ports.get(p.dport) ?? 0) + 1);
    const b = this.bucket(p.ts);
    b.packets++;
    b.bytes += p.len;
    this.flows.add(p);
    this.engine.packet(p);
    this.processingNs += (performance.now() - t0) * 1e6;
  }

  tick(now: number): void {
    this.flows.sweep(now);
    this.engine.sweep(now);
    if (this.talkers.size > 5000) {
      const keep = [...this.talkers.entries()].sort((a, b) => b[1].bytes - a[1].bytes).slice(0, 1000);
      this.talkers = new Map(keep);
    }
  }

  stats(now = Date.now()): TrafficStats {
    const s = Math.floor(now / 1000);
    return {
      ...this.totals,
      activeFlows: this.flows.active,
      protocols: { ...this.protocols },
      topTalkers: [...this.talkers.entries()].sort((a, b) => b[1].bytes - a[1].bytes).slice(0, 8).map(([ip, v]) => ({ ip, ...v })),
      topPorts: [...this.ports.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([port, packets]) => ({ port, packets })),
      series: Array.from({ length: 120 }, (_, i) => {
        const t = s - 119 + i;
        const b = this.series.get(t);
        return { t: t * 1000, packets: b?.packets ?? 0, bytes: b?.bytes ?? 0, alerts: b?.alerts ?? 0 };
      }),
    };
  }

  get avgNsPerPacket() {
    return this.totals.packets ? this.processingNs / this.totals.packets : 0;
  }
}

/** Learns what normal flows and TLS clients look like from benign simulated traffic (or a clean capture). */
export function trainBaseline(opts: { seed?: number; minutes?: number; flows?: Flow[]; tlsClients?: string[] } = {}): BaselineModel {
  let flows = opts.flows;
  const tls = new Set(opts.tlsClients ?? []);
  if (!flows) {
    const sim = new NetworkSimulator(opts.seed ?? 99);
    const start = Date.UTC(2026, 0, 1, 9);
    const packets = sim.benign(start, (opts.minutes ?? 10) * 60_000).sort((a, b) => a.ts - b.ts);
    flows = [];
    const table = new FlowTable((f) => flows!.push(f));
    for (const p of packets) {
      table.add(p);
      if (p.tls) tls.add(p.tls.ja4);
    }
    table.flush();
  }
  return { ...trainIForest(flows.map(flowVector), { trees: 120, sampleSize: 256, seed: opts.seed ?? 99 }), ...(tls.size ? { tlsClients: [...tls] } : {}) };
}

/** Fingerprint inventory: every TLS client seen, which hosts use it and what it is. */
export function tlsInventory(engine: DetectionEngine) {
  return [...engine.tlsClients.entries()]
    .map(([ja4, c]) => ({ ja4, hosts: c.hosts.size, hostList: [...c.hosts].slice(0, 12), snis: [...c.snis], connections: c.connections, first: c.first, last: c.last, profile: describeJa4(ja4) ?? null }))
    .sort((a, b) => a.hosts - b.hosts || b.last - a.last);
}
