import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG, KNOBS, whatIf } from "../src";

describe("what-if lab", () => {
  it("catches a port scan at the default threshold within a second, with no false alarms", () => {
    const r = whatIf({ kind: "port_scan", stretch: 1, threshold: KNOBS.port_scan.get(DEFAULT_CONFIG) });
    expect(r.detected).toBe(true);
    expect(r.timeToDetectMs).toBeLessThan(1000);
    expect(r.falseAlarms).toEqual([]);
    expect(r.alerts[0]).toMatchObject({ type: "port_scan", caught: true });
    expect(r.rate.reduce((a, b) => a + b, 0)).toBe(r.attackPackets);
  });

  it("a SYN flood slowed down tenfold slips under the rate threshold", () => {
    const fast = whatIf({ kind: "syn_flood", stretch: 1, threshold: 200 });
    const slow = whatIf({ kind: "syn_flood", stretch: 10, threshold: 200 });
    expect(fast.detected).toBe(true);
    expect(slow.detected).toBe(false);
    expect(slow.timeToDetectMs).toBeNull();
    expect(slow.attackSpanMs).toBeGreaterThan(fast.attackSpanMs * 5);
  });

  it("a threshold set too low raises false alarms on clean traffic", () => {
    const tuned = whatIf({ kind: "host_sweep", stretch: 1, threshold: 20 });
    const twitchy = whatIf({ kind: "host_sweep", stretch: 1, threshold: KNOBS.host_sweep.min });
    expect(tuned.falseAlarms.length).toBe(0);
    expect(twitchy.falseAlarms.length).toBeGreaterThan(0);
  });

  it("does not change the configuration it was given", () => {
    const config = structuredClone(DEFAULT_CONFIG);
    whatIf({ kind: "brute_force", stretch: 2, threshold: 3, config });
    expect(config).toEqual(DEFAULT_CONFIG);
  });
});
