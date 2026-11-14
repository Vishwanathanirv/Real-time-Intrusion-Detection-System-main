import { DEFAULT_CONFIG, type DetectorConfig } from "./detectors";
import { Sensor, trainBaseline } from "./sensor";
import { ATTACKS, EXPECTED, NetworkSimulator, type AttackKind, type LabeledPacket } from "./simulator";
import type { Alert } from "./types";

export type EvaluationReport = {
  minutes: number;
  packets: number;
  attacks: number;
  perAttack: Record<AttackKind, { injected: number; detected: number; meanTimeToDetectMs: number | null }>;
  falseAlertsPerHour: number;
  falseAlertsByType: Record<string, number>;
  throughputPps: number;
  avgMicrosPerPacket: number;
};

/**
 * Replays a labelled scenario (benign background plus scheduled attacks) through the sensor
 * and scores every detector: detection rate, time to detect, and false alerts on clean traffic.
 */
export function evaluate(opts: { seed?: number; minutes?: number; attacksPerKind?: number; config?: DetectorConfig } = {}): EvaluationReport {
  const { seed = 7, minutes = 60, attacksPerKind = 4, config = DEFAULT_CONFIG } = opts;
  const sim = new NetworkSimulator(seed);
  const start = Date.UTC(2026, 0, 5, 9);
  const packets: LabeledPacket[] = [];
  for (let m = 0; m < minutes; m++) packets.push(...sim.benign(start + m * 60_000, 60_000));
  const schedule: { id: string; kind: AttackKind; start: number; end: number }[] = [];
  let slot = 0;
  const gap = (minutes * 60_000) / (ATTACKS.length * attacksPerKind + 1);
  for (let k = 0; k < attacksPerKind; k++) {
    for (const kind of ATTACKS) {
      const a = sim.attack(kind, start + (++slot) * gap);
      packets.push(...a.packets);
      schedule.push({ id: a.id, kind, start: a.start, end: a.end });
    }
  }
  packets.sort((a, b) => a.ts - b.ts);

  const model = trainBaseline({ seed: seed + 1000 });
  const raised: { alert: Alert; ts: number }[] = [];
  const sensor = new Sensor({ config, model, onAlert: (a, isNew) => isNew && raised.push({ alert: { ...a }, ts: a.firstSeen }) });
  const t0 = performance.now();
  let lastTick = 0;
  for (const p of packets) {
    sensor.ingest(p);
    if (p.ts - lastTick > 1000) {
      sensor.tick(p.ts);
      lastTick = p.ts;
    }
  }
  sensor.flows.flush();
  const elapsed = performance.now() - t0;

  const perAttack = Object.fromEntries(ATTACKS.map((k) => [k, { injected: 0, detected: 0, meanTimeToDetectMs: null as number | null }])) as EvaluationReport["perAttack"];
  const ttd: Record<string, number[]> = {};
  const matched = new Set<Alert>();
  for (const s of schedule) {
    perAttack[s.kind].injected++;
    const hit = raised.find((r) => EXPECTED[s.kind].includes(r.alert.type) && r.ts >= s.start - 1000 && r.ts <= s.end + 130_000);
    if (hit) {
      perAttack[s.kind].detected++;
      (ttd[s.kind] ??= []).push(Math.max(0, hit.ts - s.start));
    }
    // Alerts raised during an attack window are attributable to it (e.g. a scan also tripping the anomaly model).
    for (const r of raised) if (r.ts >= s.start - 1000 && r.ts <= s.end + 130_000) matched.add(r.alert);
  }
  for (const k of ATTACKS) if (ttd[k]) perAttack[k].meanTimeToDetectMs = Math.round(ttd[k].reduce((a, b) => a + b, 0) / ttd[k].length);

  const falseAlerts = raised.filter((r) => !matched.has(r.alert));
  const falseAlertsByType: Record<string, number> = {};
  for (const f of falseAlerts) falseAlertsByType[f.alert.type] = (falseAlertsByType[f.alert.type] ?? 0) + 1;
  return {
    minutes,
    packets: packets.length,
    attacks: schedule.length,
    perAttack,
    falseAlertsPerHour: +(falseAlerts.length / (minutes / 60)).toFixed(2),
    falseAlertsByType,
    throughputPps: Math.round(packets.length / (elapsed / 1000)),
    avgMicrosPerPacket: +(sensor.avgNsPerPacket / 1000).toFixed(2),
  };
}
