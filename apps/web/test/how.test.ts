import { describe, expect, it } from "vitest";
import { traceSample } from "../src/how-data";

describe("how-it-works sample", () => {
  it("follows one real implant packet from bytes to alert", () => {
    const t = traceSample();
    // Capture: a real Ethernet/IPv4/TCP frame carrying a TLS ClientHello.
    expect(t.frame.slice(12, 14)).toEqual([0x08, 0x00]);
    expect(t.frame[54]).toBe(0x16);
    expect(t.layers.map((l) => l.to - l.from).slice(0, 3)).toEqual([14, 20, 20]);
    // Decode: the decoder reads the same addresses and computes a JA4 fingerprint.
    expect(t.fields.find((f) => f.k === "Source")!.v).toBe(t.packet.src);
    expect(t.packet.tls?.ja4).toMatch(/^t1\d/);
    // Flow: the connection, handshake included.
    expect(t.flow.established).toBe(true);
    expect(t.features).toHaveLength(10);
    // Detection: the rare-TLS detector and the Go-client signature both fire; the forest gives its score.
    expect(t.alerts.some((a) => a.type === "tls_fingerprint")).toBe(true);
    expect(t.ruleHits.some((r) => /Go TLS client/.test(r))).toBe(true);
    expect(t.rulesLoaded).toBeGreaterThan(5);
    expect(t.score).toBeGreaterThan(0);
    expect(t.score).toBeLessThan(1);
    expect(t.background).toBeGreaterThan(10_000);
  });
});
