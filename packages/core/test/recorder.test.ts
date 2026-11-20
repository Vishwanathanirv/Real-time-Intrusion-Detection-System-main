import { describe, expect, it } from "vitest";
import { FlightRecorder, frameAt, frameOf, NetworkSimulator, Sensor } from "../src";

describe("flight recorder", () => {
  it("records one frame a second, drops frames outside the window and finds the frame for any time", () => {
    const sim = new NetworkSimulator(7);
    const sensor = new Sensor({ rules: null });
    const rec = new FlightRecorder(30_000);
    const t0 = Date.UTC(2026, 0, 1);
    const pk = sim.benign(t0, 60_000);
    let next = t0 + 1000;
    for (const p of pk) {
      while (p.ts >= next) {
        sensor.tick(next);
        rec.record(frameOf(sensor.stats(next), next));
        next += 1000;
      }
      sensor.ingest(p);
    }
    const f = rec.frames;
    expect(f.length).toBeLessThanOrEqual(31);
    expect(f[f.length - 1].t - f[0].t).toBeLessThanOrEqual(30_000);
    expect(f.every((x, i) => i === 0 || x.t > f[i - 1].t)).toBe(true);
    expect(f.some((x) => x.packets > 0 && x.graph.edges.length > 0)).toBe(true);
    // every edge's hosts are in the frame
    for (const x of f) for (const e of x.graph.edges) expect(x.graph.nodes.some((n) => n.ip === e.src) && x.graph.nodes.some((n) => n.ip === e.dst)).toBe(true);
    const mid = f[10];
    expect(frameAt(f, mid.t + 500)).toBe(mid);
    expect(frameAt(f, f[0].t - 5000)).toBe(f[0]);
    expect(frameAt(f, Infinity)).toBe(f[f.length - 1]);
    expect(frameAt([], 1)).toBeUndefined();
  });

  it("ignores frames that are not newer than the last one", () => {
    const rec = new FlightRecorder();
    const g = { nodes: [], edges: [] };
    rec.record({ t: 2000, packets: 1, bytes: 1, graph: g });
    rec.record({ t: 1000, packets: 1, bytes: 1, graph: g });
    rec.record({ t: 2000, packets: 1, bytes: 1, graph: g });
    expect(rec.frames.map((x) => x.t)).toEqual([2000]);
  });
});
