import { describe, expect, it } from "vitest";
import { Sensor } from "../src/sensor";
import type { Packet } from "../src/types";

const pkt = (ts: number, src: string, dst: string, dport: number, len = 500): Packet => ({ ts, src, dst, sport: 40000, dport, proto: "tcp", flags: 0x18, payloadLen: len - 54, len, ttl: 64 });

describe("the live conversation graph", () => {
  it("lists who talks to whom, busiest first, with the ports used", () => {
    const s = new Sensor({ rules: null });
    const t = Date.now();
    for (let i = 0; i < 50; i++) s.ingest(pkt(t, "10.0.0.101", "10.0.0.20", 445));
    for (let i = 0; i < 5; i++) s.ingest(pkt(t, "10.0.0.102", "142.250.183.14", 443));
    const g = s.graph();
    expect(g.edges[0]).toMatchObject({ src: "10.0.0.101", dst: "10.0.0.20", ports: [445] });
    expect(g.nodes.find((n) => n.ip === "142.250.183.14")?.internal).toBe(false);
    expect(g.nodes.find((n) => n.ip === "10.0.0.20")?.internal).toBe(true);
  });

  it("fades quiet conversations away", () => {
    const s = new Sensor({ rules: null });
    const t = Date.now();
    for (let i = 0; i < 4; i++) s.ingest(pkt(t, "10.0.0.101", "10.0.0.2", 53, 80));
    expect(s.graph().edges).toHaveLength(1);
    s.tick(t + 5 * 60_000);
    expect(s.graph().edges).toHaveLength(0);
  });
});
