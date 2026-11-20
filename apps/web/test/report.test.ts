import { describe, expect, it } from "vitest";
import { buildReport, decodeReport, encodeReport } from "../src/report-codec";
import type { Alert, Frame } from "../src/lib";

const alert: Alert = { id: "live-1", type: "port_scan", severity: "high", title: "Port scan from 45.1.2.3", description: "45.1.2.3 probed 25 ports", src: "45.1.2.3", dst: "10.0.0.10:22", firstSeen: 100_000, lastSeen: 110_000, count: 400, mitre: { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" }, evidence: { distinctPorts: 400 }, status: "open", note: null };

const frames: Frame[] = Array.from({ length: 200 }, (_, i) => ({
  t: 20_000 + i * 1000,
  packets: 500 + i,
  bytes: 90_000,
  graph: {
    nodes: [{ ip: "45.1.2.3", bytes: 1, internal: false }, { ip: "10.0.0.10", bytes: 1, internal: true }, ...Array.from({ length: 30 }, (_, k) => ({ ip: `10.0.0.${100 + k}`, bytes: 1000, internal: true }))],
    edges: [...Array.from({ length: 30 }, (_, k) => ({ src: `10.0.0.${100 + k}`, dst: "10.0.0.10", bytes: 1000 - k, packets: 10, ports: [443] })), { src: "45.1.2.3", dst: "10.0.0.10", bytes: 10, packets: 1, ports: [22] }],
  },
}));

describe("shareable incident report", () => {
  it("keeps only the incident's window, always with its own link, and round-trips through the link", async () => {
    const r = buildReport(alert, frames, 1);
    expect(r.frames.length).toBeLessThanOrEqual(36);
    expect(r.frames[0].t).toBeGreaterThanOrEqual(alert.firstSeen - 8_000);
    expect(r.frames[r.frames.length - 1].t).toBeLessThanOrEqual(alert.lastSeen + 6_000);
    for (const f of r.frames) {
      expect(f.graph.edges.length).toBeLessThanOrEqual(10);
      expect(f.graph.edges.some((e) => e.src === "45.1.2.3")).toBe(true);
    }
    const link = await encodeReport(r);
    expect(link).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(link.length).toBeLessThan(6000);
    expect(await decodeReport(`#${link}`)).toEqual(r);
  });

  it("rejects links that are not reports", async () => {
    await expect(decodeReport("not-a-report")).rejects.toThrow();
    const bogus = await encodeReport({ v: 2 } as never);
    await expect(decodeReport(bogus)).rejects.toThrow(/does not contain a PacketEye report/);
  });
});
