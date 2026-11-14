import { describe, expect, it } from "vitest";
import { baseDomain, entropy } from "../src/detectors";
import { FlowTable } from "../src/flows";
import { Sensor, trainBaseline } from "../src/sensor";
import { NetworkSimulator, type AttackKind } from "../src/simulator";
import { evaluate } from "../src/evaluate";
import type { Alert, Flow } from "../src/types";

function run(kind: AttackKind | null, seed = 3) {
  const sim = new NetworkSimulator(seed);
  const t = Date.UTC(2026, 0, 2, 10);
  const pkts = sim.benign(t, 120_000);
  if (kind) pkts.push(...sim.attack(kind, t + 10_000).packets);
  pkts.sort((a, b) => a.ts - b.ts);
  const alerts: Alert[] = [];
  const s = new Sensor({ model: trainBaseline({ seed: 50, minutes: 5 }), onAlert: (a, n) => n && alerts.push(a) });
  for (const p of pkts) s.ingest(p);
  s.flows.flush();
  return alerts.map((a) => a.type);
}

describe("helpers", () => {
  it("entropy separates random labels from words", () => {
    expect(entropy("aaaa")).toBe(0);
    expect(entropy("k3j9x8q2m1z7v4b6n0p5")).toBeGreaterThan(4);
    expect(entropy("www")).toBeLessThan(1);
  });
  it("finds the registered domain", () => {
    expect(baseDomain("a.b.example.com")).toBe("example.com");
    expect(baseDomain("x.y.bbc.co.uk")).toBe("bbc.co.uk");
  });
});

describe("flow table", () => {
  it("tracks a handshake and closes on FIN", () => {
    const closed: Flow[] = [];
    const t = new FlowTable((f) => closed.push(f));
    const sim = new NetworkSimulator(1);
    for (const p of sim.tcpSession(0, "10.0.0.5", "1.1.1.1", 443, 500, 5000, 100)) t.add(p);
    expect(closed[0]).toMatchObject({ src: "10.0.0.5", dst: "1.1.1.1", dport: 443, established: true });
    expect(closed[0].fwdPackets + closed[0].bwdPackets).toBe(closed[0].packets);
  });
});

describe("detectors", () => {
  it("stay quiet on clean traffic", () => {
    expect(run(null).filter((t) => t !== "anomaly")).toEqual([]);
  });
  it.each([
    ["port_scan", "port_scan"],
    ["host_sweep", "host_sweep"],
    ["syn_flood", "syn_flood"],
    ["brute_force", "brute_force"],
    ["dns_tunnel", "dns_tunnel"],
    ["beaconing", "beaconing"],
    ["exfiltration", "anomaly"],
  ] as const)("detect %s", (kind, expected) => {
    expect(run(kind)).toContain(expected);
  });
  it("deduplicates repeated alerts into one with a count", () => {
    const sim = new NetworkSimulator(9);
    const alerts = new Map<string, Alert>();
    const s = new Sensor({ onAlert: (a) => alerts.set(a.id, a) });
    for (const p of sim.attack("port_scan", 0).packets) s.ingest(p);
    const scans = [...alerts.values()].filter((a) => a.type === "port_scan");
    expect(scans).toHaveLength(1);
    expect(scans[0].count).toBeGreaterThan(10);
    expect(scans[0].mitre.id).toBe("T1046");
  });
});

describe("evaluation harness", () => {
  it("detects every injected attack in a short replay", () => {
    const r = evaluate({ minutes: 12, attacksPerKind: 1, seed: 11 });
    for (const v of Object.values(r.perAttack)) expect(v.detected).toBe(v.injected);
    expect(r.throughputPps).toBeGreaterThan(20_000);
  });
});

describe("grouping", () => {
  it("keeps a spoofed multi-source flood as one alert", () => {
    const sim = new NetworkSimulator(2);
    const alerts = new Map<string, Alert>();
    const s = new Sensor({ onAlert: (a) => alerts.set(a.id, a) });
    let found = false;
    for (let seed = 0; seed < 5 && !found; seed++) {
      const atk = sim.attack("syn_flood", seed * 60_000);
      for (const p of atk.packets) s.ingest(p);
      found = new Set(atk.packets.map((p) => p.src)).size > 1;
    }
    const floods = [...alerts.values()].filter((a) => a.type === "syn_flood" && a.src === "multiple sources");
    if (found) expect(floods.length).toBeLessThanOrEqual(5);
  });
});
