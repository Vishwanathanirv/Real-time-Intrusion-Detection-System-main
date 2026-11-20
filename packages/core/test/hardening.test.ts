import { describe, expect, it } from "vitest";
import { FlowTable } from "../src/flows";
import { decodeFrame, writePcap } from "../src/pcap";
import { TCP, type Flow, type Packet } from "../src/types";

const pk = (o: Partial<Packet> = {}): Packet => ({ ts: 1_700_000_000_000, src: "10.0.0.5", dst: "93.184.216.34", sport: 51515, dport: 443, proto: "tcp", len: 74, flags: TCP.SYN, ttl: 64, payloadLen: 0, ...o });
/** One Ethernet frame, without the pcap file and record headers. */
const frameOf = (p: Packet) => writePcap([p]).slice(40);

describe("decoder hardening", () => {
  it("skips later IP fragments instead of reading payload bytes as ports", () => {
    const f = frameOf(pk({ flags: TCP.ACK, payloadLen: 200 }));
    f[14 + 6] = 0x00;
    f[14 + 7] = 0xb9; // fragment offset 185 * 8 bytes
    expect(decodeFrame(f, 1, 0, f.length)).toBeNull();
    const first = frameOf(pk({}));
    first[14 + 6] = 0x20; // more-fragments flag, offset 0: still has the TCP header
    expect(decodeFrame(first, 1, 0, first.length)?.dport).toBe(443);
  });

  it("rejects impossible IPv4 and TCP header lengths", () => {
    const badIhl = frameOf(pk({}));
    badIhl[14] = 0x41; // IHL of 4 bytes
    expect(decodeFrame(badIhl, 1, 0, badIhl.length)).toBeNull();
    const badOff = frameOf(pk({}));
    badOff[14 + 20 + 12] = 0x10; // TCP data offset of 4 bytes
    expect(decodeFrame(badOff, 1, 0, badOff.length)).toBeNull();
  });

  it("accepts a zero IP total length from TCP segmentation offload", () => {
    const f = frameOf(pk({ flags: TCP.ACK | TCP.PSH, payloadLen: 100 }));
    f[14 + 2] = 0;
    f[14 + 3] = 0;
    const p = decodeFrame(f, 1, 0, f.length);
    expect(p?.dport).toBe(443);
    expect(p?.payloadLen).toBe(100);
  });

  it("decodes Linux cooked capture v2 (tcpdump -i any)", () => {
    const eth = frameOf(pk({}));
    const sll2 = new Uint8Array(20 + eth.length - 14);
    sll2.set([0x08, 0x00], 0);
    sll2.set(eth.subarray(14), 20);
    expect(decodeFrame(sll2, 276, 0, sll2.length)?.dport).toBe(443);
  });
});

describe("flow table limits", () => {
  it("caps memory under a spoofed-source flood by evicting the oldest flows", () => {
    const closed: Flow[] = [];
    const t = new FlowTable((f) => closed.push(f), 30_000, 120_000, 1000);
    for (let i = 0; i < 5000; i++) t.add(pk({ src: `198.18.${i >> 8}.${i & 255}`, sport: 1024 + i }));
    expect(t.active).toBe(1000);
    expect(t.evicted).toBe(4000);
    expect(closed[0].src).toBe("198.18.0.0");
  });

  it("closes a flow on RST without leaking the entry", () => {
    const t = new FlowTable(() => {});
    t.add(pk({}));
    t.add(pk({ src: "93.184.216.34", dst: "10.0.0.5", sport: 443, dport: 51515, flags: TCP.RST }));
    expect(t.active).toBe(0);
  });
});
