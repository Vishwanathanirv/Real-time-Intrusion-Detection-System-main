import { spawn, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { ATTACKS, DEFAULT_RULES, NetworkSimulator, PcapStreamReader, Sensor, trainBaseline, type Alert, type AttackKind, type DetectorConfig, type LabeledPacket, type Packet } from "@packeteye/core";

export type Mode = "simulator" | "capture";
export type LiveState = { mode: Mode; running: boolean; autopilot: boolean; interface?: string; activeAttacks: { id: string; kind: AttackKind; endsAt: number }[] };

/**
 * The live sensor. In simulator mode it generates office traffic in real time and injects
 * attacks on demand (or automatically). In capture mode it parses `tcpdump -w -` from a real interface.
 */
export class LiveSensor extends EventEmitter {
  sensor: Sensor;
  readonly sim = new NetworkSimulator(Date.now() % 100_000);
  readonly state: LiveState;
  private queue: LabeledPacket[] = [];
  private timers: NodeJS.Timeout[] = [];
  private tcpdump: ChildProcess | null = null;
  private nextAuto = Date.now() + 20_000;
  /** The active ruleset, kept here so a sensor reset keeps the operator's rules. */
  rulesText = DEFAULT_RULES;

  constructor(private config: DetectorConfig, opts: { mode?: Mode; iface?: string; autopilot?: boolean } = {}) {
    super();
    this.setMaxListeners(100);
    this.state = { mode: opts.mode ?? "simulator", running: false, autopilot: opts.autopilot ?? true, interface: opts.iface, activeAttacks: [] };
    this.sensor = this.makeSensor();
  }

  private makeSensor() {
    return new Sensor({ config: this.config, model: trainBaseline({ seed: 99, minutes: 8 }), rules: this.rulesText, onAlert: (a: Alert, isNew: boolean) => this.emit("alert", a, isNew) });
  }

  start() {
    if (this.state.running) return;
    this.state.running = true;
    if (this.state.mode === "capture") this.startCapture();
    else {
      let last = Date.now();
      this.timers.push(
        setInterval(() => {
          const now = Date.now();
          this.queue.push(...this.sim.benign(last, now - last));
          last = now;
          if (this.state.autopilot && now >= this.nextAuto) {
            this.launch(ATTACKS[Math.floor(Math.random() * ATTACKS.length)]);
            this.nextAuto = now + 45_000 + Math.random() * 60_000;
          }
        }, 250),
      );
      this.timers.push(setInterval(() => this.drain(), 50));
    }
    this.timers.push(
      setInterval(() => {
        const now = Date.now();
        this.sensor.tick(now);
        this.state.activeAttacks = this.state.activeAttacks.filter((a) => a.endsAt > now);
        this.emit("stats", this.sensor.stats(now));
      }, 1000),
    );
  }

  private drain() {
    const now = Date.now();
    if (!this.queue.length) return;
    this.queue.sort((a, b) => a.ts - b.ts);
    let i = 0;
    while (i < this.queue.length && this.queue[i].ts <= now) this.sensor.ingest(this.queue[i++]);
    this.queue.splice(0, i);
    if (this.queue.length > 400_000) this.queue.splice(0, this.queue.length - 400_000);
  }

  /** Schedules an attack to unfold in real time from now. */
  launch(kind: AttackKind) {
    if (this.state.mode !== "simulator") throw new Error("Attacks can only be simulated in simulator mode.");
    const a = this.sim.attack(kind, Date.now() + 200);
    // Long campaigns are compressed so the demo stays snappy.
    const span = a.end - a.start;
    const factor = span > 90_000 ? 90_000 / span : 1;
    for (const p of a.packets) this.queue.push({ ...p, ts: a.start + (p.ts - a.start) * factor });
    const info = { id: a.id, kind, endsAt: a.start + span * factor + 2_000 };
    this.state.activeAttacks.push(info);
    this.emit("attack", info);
    return info;
  }

  private startCapture() {
    const iface = this.state.interface ?? "any";
    const reader = new PcapStreamReader((p: Packet) => this.sensor.ingest({ ...p, ts: Date.now() }));
    this.tcpdump = spawn("tcpdump", ["-i", iface, "-U", "-s", "256", "-w", "-", "not port 8080"], { stdio: ["ignore", "pipe", "pipe"] });
    this.tcpdump.stdout!.on("data", (c: Buffer) => {
      try {
        reader.push(new Uint8Array(c.buffer, c.byteOffset, c.byteLength));
      } catch (e) {
        this.emit("error", e);
      }
    });
    this.tcpdump.on("error", (e) => this.emit("error", new Error(`Could not start tcpdump (${e.message}). Install it and run with CAP_NET_RAW, or use simulator mode.`)));
  }

  setAutopilot(on: boolean) {
    this.state.autopilot = on;
    this.nextAuto = Date.now() + 10_000;
  }

  reset() {
    this.queue = [];
    this.sensor = this.makeSensor();
  }

  stop() {
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    this.tcpdump?.kill();
    this.tcpdump = null;
    this.state.running = false;
  }
}
