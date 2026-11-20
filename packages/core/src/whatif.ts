import { DEFAULT_CONFIG, type BaselineModel, type DetectorConfig } from "./detectors";
import { ATTACK_LABELS, EXPECTED, NetworkSimulator, type AttackKind, type LabeledPacket } from "./simulator";
import { Sensor } from "./sensor";
import type { Alert } from "./types";

/**
 * The what-if lab: replays one attack against an isolated sensor, with the attacker slowed down
 * and one detector threshold changed, and reports whether it is still caught, how fast, and how
 * many false alarms the same threshold raises on clean traffic. It is the trade-off every analyst
 * tunes, made visible.
 */

/** The one threshold that matters most for each attack, with a range worth exploring. */
export const KNOBS: Record<AttackKind, { label: string; unit: string; min: number; max: number; step: number; get: (c: DetectorConfig) => number; set: (c: DetectorConfig, v: number) => void; hint: string }> = {
  port_scan: {
    label: "Ports before alerting",
    unit: "ports in 15 s",
    min: 5,
    max: 400,
    step: 5,
    get: (c) => c.portScan.distinctPorts,
    set: (c, v) => void (c.portScan.distinctPorts = v),
    hint: "Lower catches slower scans, but busy clients start to look like scanners.",
  },
  host_sweep: {
    label: "Hosts before alerting",
    unit: "hosts in 30 s",
    min: 3,
    max: 200,
    step: 1,
    get: (c) => c.hostSweep.distinctHosts,
    set: (c, v) => void (c.hostSweep.distinctHosts = v),
    hint: "Lower catches quieter sweeps; too low and the DNS server's clients trip it.",
  },
  syn_flood: {
    label: "SYN packets per second",
    unit: "SYN/s at one target",
    min: 20,
    max: 3000,
    step: 10,
    get: (c) => c.synFlood.synPerSec,
    set: (c, v) => void (c.synFlood.synPerSec = v),
    hint: "A flood only works if it is fast, so slowing it down also blunts it.",
  },
  brute_force: {
    label: "Login attempts",
    unit: "attempts per minute",
    min: 2,
    max: 80,
    step: 1,
    get: (c) => c.bruteForce.attempts,
    set: (c, v) => void (c.bruteForce.attempts = v),
    hint: "Slow guessing hides under a high threshold; a low one flags admins who reconnect a lot.",
  },
  dns_tunnel: {
    label: "Subdomain entropy",
    unit: "bits per character",
    min: 2,
    max: 5,
    step: 0.1,
    get: (c) => c.dnsTunnel.entropy,
    set: (c, v) => void (c.dnsTunnel.entropy = Math.round(v * 10) / 10),
    hint: "Encoded data looks random. Lower catches more, and starts flagging CDN hostnames.",
  },
  beaconing: {
    label: "Allowed timing jitter",
    unit: "coefficient of variation",
    min: 0.01,
    max: 0.6,
    step: 0.01,
    get: (c) => c.beacon.maxJitter,
    set: (c, v) => void (c.beacon.maxJitter = Math.round(v * 100) / 100),
    hint: "Implants call home on a timer. Allow more jitter and you catch sloppier timers.",
  },
  exfiltration: {
    label: "Anomaly score cut-off",
    unit: "isolation-forest score",
    min: 0.5,
    max: 0.9,
    step: 0.01,
    get: (c) => c.anomaly.threshold,
    set: (c, v) => void (c.anomaly.threshold = Math.round(v * 100) / 100),
    hint: "The model has never seen an attack. A lower cut-off trusts it more, and so does the noise.",
  },
  tls_c2: {
    label: "Hosts that make a client common",
    unit: "internal hosts",
    min: 1,
    max: 12,
    step: 1,
    get: (c) => c.tls.commonHosts,
    set: (c, v) => void (c.tls.commonHosts = v),
    hint: "A fingerprint seen on fewer hosts than this is rare. At 1, nothing is ever rare.",
  },
};

export type WhatIfInput = { kind: AttackKind; stretch: number; threshold: number; seed?: number; model?: BaselineModel | null; config?: DetectorConfig };

export type WhatIfResult = {
  kind: AttackKind;
  label: string;
  stretch: number;
  threshold: number;
  detected: boolean;
  /** Milliseconds from the attack's first packet to the first alert that counts as catching it. */
  timeToDetectMs: number | null;
  attackPackets: number;
  attackSpanMs: number;
  windowMs: number;
  /** Clean traffic before the attack starts. */
  leadMs: number;
  /** Alerts raised while the attack ran, relative to its first packet. */
  alerts: { type: string; title: string; severity: Alert["severity"]; atMs: number; caught: boolean }[];
  /** Alerts the same settings raise on the same clean traffic with no attack: false alarms. */
  falseAlarms: { type: string; title: string }[];
  /** Packets per second of the attack, to draw it. */
  rate: number[];
};

const LEAD = 10_000;
const TAIL = 25_000;
const MAX_ATTACK = 240_000;

function run(packets: LabeledPacket[], config: DetectorConfig, model: BaselineModel | null, end: number) {
  const alerts: Alert[] = [];
  const sensor = new Sensor({ config, model, onAlert: (a, isNew) => isNew && alerts.push({ ...a }) });
  let tick = packets[0]?.ts ?? 0;
  for (const p of packets) {
    while (p.ts - tick >= 1000) {
      tick += 1000;
      sensor.tick(tick);
    }
    sensor.ingest(p);
  }
  for (; tick < end; tick += 1000) sensor.tick(tick);
  sensor.flows.flush();
  sensor.tick(end + 1);
  return alerts;
}

export function whatIf(input: WhatIfInput): WhatIfResult {
  const config = structuredClone(input.config ?? DEFAULT_CONFIG);
  KNOBS[input.kind].set(config, input.threshold);
  const stretch = Math.max(1, Math.min(30, input.stretch));
  const sim = new NetworkSimulator(input.seed ?? 11);
  const t0 = Date.UTC(2026, 0, 5, 9);
  const raw = sim.attack(input.kind, t0 + LEAD);
  const attack = raw.packets.map((p) => ({ ...p, ts: raw.start + (p.ts - raw.start) * stretch })).filter((p) => p.ts - raw.start <= MAX_ATTACK);
  const span = attack.length ? attack[attack.length - 1].ts - raw.start : 0;
  const windowMs = LEAD + span + TAIL;
  const benign = sim.benign(t0, windowMs);
  const mixed = [...benign, ...attack].sort((a, b) => a.ts - b.ts);
  const end = t0 + windowMs;
  const withAttack = run(mixed, config, input.model ?? null, end);
  const clean = run(benign, structuredClone(config), input.model ?? null, end);
  const cleanKeys = new Set(clean.map((a) => `${a.type}|${a.src}|${a.dst}`));
  const expected = EXPECTED[input.kind];
  const alerts = withAttack
    .filter((a) => a.firstSeen >= raw.start - 1000 && !cleanKeys.has(`${a.type}|${a.src}|${a.dst}`))
    .map((a) => ({ type: a.type, title: a.title, severity: a.severity, atMs: Math.round(a.firstSeen - raw.start), caught: expected.includes(a.type) }))
    .sort((a, b) => a.atMs - b.atMs);
  const first = alerts.find((a) => a.caught);
  const buckets = Math.max(1, Math.ceil(windowMs / 1000));
  const rate = new Array<number>(buckets).fill(0);
  for (const p of attack) rate[Math.min(buckets - 1, Math.floor((p.ts - t0) / 1000))]++;
  return {
    kind: input.kind,
    label: ATTACK_LABELS[input.kind],
    stretch,
    threshold: input.threshold,
    detected: Boolean(first),
    timeToDetectMs: first ? Math.max(0, first.atMs) : null,
    attackPackets: attack.length,
    attackSpanMs: Math.round(span),
    windowMs,
    leadMs: LEAD,
    alerts,
    falseAlarms: clean.map((a) => ({ type: a.type, title: a.title })),
    rate,
  };
}
