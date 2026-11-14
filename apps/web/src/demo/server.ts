import {
  ATTACKS,
  ATTACK_LABELS,
  DEFAULT_CONFIG,
  NetworkSimulator,
  PcapStreamReader,
  Sensor,
  trainBaseline,
  writePcap,
  type Alert as CoreAlert,
  type AttackKind,
  type DetectorConfig,
  type IForestModel,
  type LabeledPacket,
} from "@packeteye/core";
import type { Alert, Stats } from "../lib";

/**
 * In-browser version of the PacketEye server, used for the hosted demo. The simulated office
 * network, flow table, detectors and isolation forest are the same code the Node sensor runs;
 * only the transport is different (events instead of a WebSocket). Each visitor gets a private
 * sandbox, and uploaded captures are analysed locally without leaving the machine.
 */

type Message = { type: string; data: unknown };
type Listener = (m: Message) => void;
type State = Stats["state"];

class DemoSensor {
  private config: DetectorConfig = structuredClone(DEFAULT_CONFIG);
  private model!: IForestModel;
  sensor!: Sensor;
  private sim = new NetworkSimulator(Date.now() % 100_000);
  private queue: LabeledPacket[] = [];
  private alerts = new Map<string, Alert>();
  private dirty = new Map<string, Alert>();
  private listeners = new Set<Listener>();
  private nextAuto = Date.now() + 25_000;
  state: State = { mode: "simulator", running: true, autopilot: true, activeAttacks: [] };
  readonly ready: Promise<void>;

  constructor() {
    this.ready = this.boot();
  }

  private async boot() {
    await new Promise((r) => setTimeout(r, 0));
    this.model = trainBaseline({ seed: 99, minutes: 8 });
    this.sensor = new Sensor({ config: this.config, model: this.model, onAlert: (a, isNew) => this.onAlert(a, isNew) });
    // Backfill two minutes of traffic, with a scan and a brute-force attempt already under way,
    // so the chart and alert list are populated when the page opens.
    const now = Date.now();
    const from = now - 120_000;
    const pk: LabeledPacket[] = this.sim.benign(from, 120_000);
    pk.push(...this.sim.attack("port_scan", now - 95_000).packets, ...this.sim.attack("brute_force", now - 50_000).packets);
    pk.sort((a, b) => a.ts - b.ts);
    let tick = from;
    for (const p of pk) {
      if (p.ts > now) this.queue.push(p);
      else {
        this.sensor.ingest(p);
        if (p.ts - tick >= 1000) {
          this.sensor.tick(p.ts);
          tick = p.ts;
        }
      }
    }
    this.dirty.clear();
    this.run();
  }

  private onAlert(a: CoreAlert, isNew: boolean) {
    const id = `live-${a.id}`;
    const prev = this.alerts.get(id);
    const stored: Alert = { ...a, id, status: prev?.status ?? "open", note: prev?.note ?? null };
    this.alerts.set(id, stored);
    if (isNew) {
      this.dirty.delete(id);
      this.emit({ type: "alert", data: stored });
    } else this.dirty.set(id, stored);
  }

  private run() {
    let last = Date.now();
    setInterval(() => {
      if (!this.state.running) return;
      const now = Date.now();
      this.queue.push(...this.sim.benign(last, now - last));
      last = now;
      if (this.state.autopilot && now >= this.nextAuto) {
        this.launch(ATTACKS[Math.floor(Math.random() * ATTACKS.length)]);
        this.nextAuto = now + 45_000 + Math.random() * 60_000;
      }
    }, 250);
    setInterval(() => this.drain(), 50);
    setInterval(() => {
      const now = Date.now();
      this.sensor.tick(now);
      this.state.activeAttacks = this.state.activeAttacks.filter((a) => a.endsAt > now);
      for (const a of this.dirty.values()) this.emit({ type: "alert-update", data: a });
      this.dirty.clear();
      this.emit({ type: "stats", data: this.stats(now) });
    }, 1000);
  }

  private drain() {
    if (!this.queue.length) return;
    const now = Date.now();
    this.queue.sort((a, b) => a.ts - b.ts);
    let i = 0;
    while (i < this.queue.length && this.queue[i].ts <= now) this.sensor.ingest(this.queue[i++]);
    this.queue.splice(0, i);
    if (this.queue.length > 400_000) this.queue.splice(0, this.queue.length - 400_000);
  }

  private stats(now = Date.now()): Stats {
    return { ...this.sensor.stats(now), state: this.state, avgMicrosPerPacket: +(this.sensor.avgNsPerPacket / 1000).toFixed(2) };
  }

  launch(kind: AttackKind) {
    const a = this.sim.attack(kind, Date.now() + 200);
    const span = a.end - a.start;
    const factor = span > 90_000 ? 90_000 / span : 1;
    for (const p of a.packets) this.queue.push({ ...p, ts: a.start + (p.ts - a.start) * factor });
    const info = { id: a.id, kind, endsAt: a.start + span * factor + 2_000 };
    this.state.activeAttacks.push(info);
    this.emit({ type: "attack", data: info });
    return info;
  }

  private emit(m: Message) {
    for (const l of this.listeners) l(m);
  }

  async subscribe(l: Listener) {
    await this.ready;
    this.listeners.add(l);
    l({ type: "hello", data: { state: this.state, stats: this.sensor.stats() } });
    return () => void this.listeners.delete(l);
  }

  // ---------- request handling ----------

  async handle(method: string, url: string, body: unknown): Promise<{ status: number; data: unknown }> {
    await this.ready;
    const u = new URL(url, "http://demo.local");
    const p = u.pathname;
    const q = Object.fromEntries(u.searchParams);
    if (method === "GET" && p === "/api/health") return ok({ ok: true, mode: "simulator", running: this.state.running, notifications: false, browser: true });
    if (method === "GET" && p === "/api/stats") return ok(this.stats());
    if (method === "GET" && p === "/api/alerts") {
      const limit = Math.min(Number(q.limit ?? 100) || 100, 500);
      const list = [...this.alerts.values()]
        .filter((a) => (!q.status || a.status === q.status) && (!q.severity || a.severity === q.severity) && (!q.type || a.type === q.type))
        .sort((a, b) => b.lastSeen - a.lastSeen)
        .slice(0, limit);
      return ok({ alerts: list });
    }
    const m = p.match(/^\/api\/alerts\/([^/]+)$/);
    if (m) {
      const a = this.alerts.get(decodeURIComponent(m[1]));
      if (!a) return err(404, "Not found");
      if (method === "GET") return ok({ alert: a });
      if (method === "PATCH") {
        const b = (body ?? {}) as { status?: string; note?: string };
        if (!["open", "acknowledged", "resolved"].includes(b.status ?? "")) return err(400, "status: invalid status");
        if (b.note && b.note.length > 500) return err(400, "note: at most 500 characters");
        a.status = b.status as Alert["status"];
        if (b.note !== undefined) a.note = b.note;
        return ok({ alert: a });
      }
    }
    if (method === "GET" && p === "/api/attacks") return ok({ attacks: ATTACKS.map((k) => ({ kind: k, label: ATTACK_LABELS[k] })), active: this.state.activeAttacks });
    if (method === "POST" && p === "/api/attacks") {
      const kind = (body as { kind?: string })?.kind as AttackKind;
      if (!ATTACKS.includes(kind)) return err(400, "kind: unknown attack");
      return ok({ attack: this.launch(kind) });
    }
    if (method === "PUT" && p === "/api/live") {
      const b = (body ?? {}) as { autopilot?: boolean; running?: boolean };
      if (b.autopilot !== undefined) {
        this.state.autopilot = b.autopilot;
        this.nextAuto = Date.now() + 10_000;
      }
      if (b.running !== undefined) this.state.running = b.running;
      return ok({ state: this.state });
    }
    if (method === "GET" && p === "/api/config") return ok({ config: this.config });
    if (method === "GET" && p === "/api/evaluation") {
      const r = await fetch("/evaluation.json");
      return r.ok ? ok(await r.json()) : err(404, "Evaluation report not found.");
    }
    return err(404, "Not found");
  }

  /** Runs a capture through an isolated sensor, entirely on this machine. */
  async analyze(file: File) {
    await this.ready;
    if (file.size > 50 * 1024 * 1024) throw new Error("File is larger than 50 MB.");
    const found = new Map<string, Alert>();
    const sensor = new Sensor({ config: this.config, model: this.model, onAlert: (a) => found.set(a.id, { ...a }) });
    let first = Infinity;
    let last = 0;
    let tick = 0;
    const reader = new PcapStreamReader((pk) => {
      first = Math.min(first, pk.ts);
      last = Math.max(last, pk.ts);
      sensor.ingest(pk);
      if (pk.ts - tick > 1000) {
        sensor.tick(pk.ts);
        tick = pk.ts;
      }
    });
    const stream = file.stream().getReader();
    for (;;) {
      const { done, value } = await stream.read();
      if (done) break;
      reader.push(value);
    }
    sensor.flows.flush();
    const s = sensor.stats(last);
    return {
      file: file.name,
      packets: reader.packets,
      skipped: reader.skipped,
      durationSec: reader.packets ? +((last - first) / 1000).toFixed(1) : 0,
      flows: s.flows,
      bytes: s.bytes,
      protocols: s.protocols,
      topTalkers: s.topTalkers,
      topPorts: s.topPorts,
      alerts: [...found.values()].sort((a, b) => a.firstSeen - b.firstSeen),
    };
  }

  /** The same sample capture the server offers: a minute of office traffic plus every attack type. */
  samplePcap(): Blob {
    const sim = new NetworkSimulator(4242);
    const t = Date.UTC(2026, 0, 3, 10);
    const pk = sim.benign(t, 60_000);
    let at = t + 5_000;
    for (const k of ATTACKS) {
      pk.push(...sim.attack(k, at).packets);
      at += 12_000;
    }
    pk.sort((a, b) => a.ts - b.ts);
    return new Blob([writePcap(pk, 128) as Uint8Array<ArrayBuffer>], { type: "application/vnd.tcpdump.pcap" });
  }
}

const ok = (data: unknown) => ({ status: 200, data });
const err = (status: number, error: string) => ({ status, data: { error } });

export const demo = new DemoSensor();
