import { describe, expect, it } from "vitest";
import { PcapStreamReader, decodeFrame, readPcap, writePcap } from "../src/pcap";
import { TCP, type Packet } from "../src/types";

const pk = (o: Partial<Packet>): Packet => ({ ts: 1_700_000_000_123.456, src: "10.0.0.5", dst: "93.184.216.34", sport: 51515, dport: 443, proto: "tcp", len: 74, flags: TCP.SYN, ttl: 64, payloadLen: 0, ...o });

describe("pcap", () => {
  const packets = [
    pk({}),
    pk({ proto: "udp", sport: 5353, dport: 53, flags: 0, dnsQuery: "api.github.com", payloadLen: 32 }),
    pk({ proto: "icmp", sport: 0, dport: 0, flags: 0, payloadLen: 56 }),
    pk({ flags: TCP.ACK | TCP.PSH, payloadLen: 900, len: 954 }),
  ];

  it("round-trips packets through write and read", () => {
    const { packets: back, skipped } = readPcap(writePcap(packets));
    expect(skipped).toBe(0);
    expect(back).toHaveLength(4);
    expect(back[0]).toMatchObject({ src: "10.0.0.5", dst: "93.184.216.34", sport: 51515, dport: 443, proto: "tcp", flags: TCP.SYN, ttl: 64 });
    expect(back[0].ts).toBeCloseTo(packets[0].ts, 2);
    expect(back[1].dnsQuery).toBe("api.github.com");
    expect(back[2].proto).toBe("icmp");
    expect(back[3].payloadLen).toBe(900);
  });

  it("parses a stream split at arbitrary byte boundaries", () => {
    const bytes = writePcap(packets);
    const got: Packet[] = [];
    const r = new PcapStreamReader((p) => got.push(p));
    for (let i = 0; i < bytes.length; i += 7) r.push(bytes.subarray(i, i + 7));
    expect(got.map((p) => p.dport)).toEqual([443, 53, 0, 443]);
  });

  it("handles VLAN tags and ignores non-IPv4 frames", () => {
    const frame = writePcap([pk({})]).subarray(40);
    const tagged = new Uint8Array(frame.length + 4);
    tagged.set(frame.subarray(0, 12));
    tagged.set([0x81, 0x00, 0x00, 0x64], 12);
    tagged.set(frame.subarray(12), 16);
    expect(decodeFrame(tagged, 1, 0, tagged.length)?.dport).toBe(443);
    const arp = new Uint8Array(42);
    arp[12] = 0x08;
    arp[13] = 0x06;
    expect(decodeFrame(arp, 1, 0, 42)).toBeNull();
  });

  it("rejects files that are not pcap", () => {
    expect(() => readPcap(new Uint8Array(32).fill(7))).toThrow(/pcap/);
  });
});

describe("snaplen", () => {
  it("truncates stored bytes but keeps headers, DNS names and original lengths", () => {
    const big: Packet = { ts: 1, src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 445, proto: "tcp", len: 1454, flags: 0x18, ttl: 64, payloadLen: 1400 };
    const dns: Packet = { ...big, proto: "udp", dport: 53, len: 80, payloadLen: 30, flags: 0, dnsQuery: "a.example.com" };
    const bytes = writePcap([big, dns], 128);
    expect(bytes.length).toBeLessThan(24 + 2 * (16 + 128) + 1);
    const { packets } = readPcap(bytes);
    expect(packets[0]).toMatchObject({ dport: 445, payloadLen: 1400, len: 1454 });
    expect(packets[1].dnsQuery).toBe("a.example.com");
  });
});
