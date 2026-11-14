import { describe, expect, it } from "vitest";
import { DEFAULT_RULES, NetworkSimulator, RuleLimiter, Sensor, compileRules, readPcap, trainBaseline, writePcap, type Alert, type Packet } from "../src/index";

const pkt = (o: Partial<Packet>): Packet => ({ ts: 1000, src: "10.0.0.5", dst: "45.1.2.3", sport: 50000, dport: 443, proto: "tcp", len: 60, flags: 0x02, ttl: 64, payloadLen: 0, ...o });

describe("rule language", () => {
  it("compiles the default ruleset without errors", () => {
    const { rules, errors } = compileRules(DEFAULT_RULES);
    expect(errors).toEqual([]);
    expect(rules.length).toBeGreaterThanOrEqual(8);
  });

  it("matches addresses, CIDRs, negation, port lists and ranges", () => {
    const { rules } = compileRules(`alert tcp [10.0.0.0/24,!10.0.0.9] any -> !$HOME_NET [443,8000:8100] (msg:"x"; flags:S; sid:1;)`);
    const r = rules[0];
    expect(r.match(pkt({}))).not.toBeNull();
    expect(r.match(pkt({ dport: 8050 }))).not.toBeNull();
    expect(r.match(pkt({ src: "10.0.0.9" }))).toBeNull();
    expect(r.match(pkt({ dst: "10.0.0.20" }))).toBeNull();
    expect(r.match(pkt({ dport: 80 }))).toBeNull();
    expect(r.match(pkt({ flags: 0x12 }))).toBeNull(); // SYN-ACK is not "S"
  });

  it("supports bidirectional rules", () => {
    const { rules } = compileRules(`alert tcp 10.0.0.5 any <> 45.1.2.3 443 (msg:"x"; sid:2;)`);
    expect(rules[0].match(pkt({}))).not.toBeNull();
    expect(rules[0].match(pkt({ src: "45.1.2.3", dst: "10.0.0.5", sport: 443, dport: 50000 }))).not.toBeNull();
  });

  it("matches sticky buffers with content modifiers and pcre", () => {
    const { rules, errors } = compileRules(
      [
        `alert dns any any -> any 53 (msg:"ddns"; dns.query; content:".DuckDNS.org"; endswith; nocase; sid:3;)`,
        `alert tls any any -> any any (msg:"ja4"; ja4.hash; content:"t13d1516"; startswith; tls.sni; pcre:"/^mail\\./"; sid:4;)`,
      ].join("\n"),
    );
    expect(errors).toEqual([]);
    expect(rules[0].match(pkt({ proto: "udp", dport: 53, dnsQuery: "evil.duckdns.org" }))).toBe("dns.query: evil.duckdns.org");
    expect(rules[0].match(pkt({ proto: "udp", dport: 53, dnsQuery: "duckdns.org.example.com" }))).toBeNull();
    const tls = { ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1", sni: "mail.example.com" };
    expect(rules[1].match(pkt({ flags: 0x18, tls }))).not.toBeNull();
    expect(rules[1].match(pkt({ flags: 0x18, tls: { ...tls, sni: "www.example.com" } }))).toBeNull();
  });

  it("reports errors with line numbers instead of ignoring them", () => {
    const { rules, errors } = compileRules(
      [
        "# comment",
        `alert tcp any any -> any any (msg:"ok"; sid:10;)`,
        `alert tcp any any -> any any (msg:"payload"; content:"GET"; sid:11;)`,
        `alert foo any any -> any any (msg:"proto"; sid:12;)`,
        `alert tcp any any -> any any (msg:"dup"; sid:10;)`,
        `alert tcp $NOPE any -> any any (msg:"var"; sid:13;)`,
        `alert tcp any any -> any any (msg:"kw"; http.uri; sid:14;)`,
      ].join("\n"),
    );
    expect(rules).toHaveLength(1);
    expect(errors.map((e) => e.line)).toEqual([3, 4, 5, 6, 7]);
    expect(errors[0].message).toMatch(/sticky buffer/);
    expect(errors[2].message).toMatch(/duplicate sid 10/);
    expect(errors[3].message).toMatch(/unknown variable/);
    expect(errors[4].message).toMatch(/unsupported keyword "http.uri"/);
  });

  it("joins rules split over lines with a backslash", () => {
    const { rules, errors } = compileRules(`alert tcp any any -> any 22 \\\n  (msg:"ssh"; flags:S; \\\n  sid:20;)`);
    expect(errors).toEqual([]);
    expect(rules[0].line).toBe(1);
  });

  it("applies threshold and detection_filter semantics", () => {
    const { rules } = compileRules(
      [
        `alert icmp any any -> any any (msg:"both"; threshold:type both, track by_src, count 3, seconds 10; sid:30;)`,
        `alert icmp any any -> any any (msg:"limit"; threshold:type limit, track by_src, count 2, seconds 10; sid:31;)`,
        `alert icmp any any -> any any (msg:"filter"; detection_filter:track by_src, count 2, seconds 10; sid:32;)`,
      ].join("\n"),
    );
    const lim = new RuleLimiter();
    const fires = (r: (typeof rules)[number]) => [0, 1, 2, 3, 4].map((i) => lim.allow(r, pkt({ proto: "icmp", ts: 1000 + i * 100 })));
    expect(fires(rules[0])).toEqual([false, false, true, false, false]);
    expect(fires(rules[1])).toEqual([true, true, false, false, false]);
    expect(fires(rules[2])).toEqual([false, false, true, true, true]);
  });
});

describe("TLS in the sensor", () => {
  it("keeps JA4 fingerprints through a pcap round trip", () => {
    const sim = new NetworkSimulator(3);
    const pk = sim.benign(Date.UTC(2026, 0, 1, 9), 5_000).sort((a, b) => a.ts - b.ts);
    const withTls = pk.filter((p) => p.tls);
    expect(withTls.length).toBeGreaterThan(5);
    const back = readPcap(writePcap(pk, 128)).packets.filter((p) => p.tls);
    expect(back.map((p) => p.tls!.ja4)).toEqual(withTls.map((p) => p.tls!.ja4));
    expect(back.map((p) => p.tls!.sni)).toEqual(withTls.map((p) => p.tls!.sni));
  });

  it("flags an implant's rare TLS client but not the office's browsers", () => {
    const sim = new NetworkSimulator(11);
    const t = Date.UTC(2026, 0, 2, 9);
    const pk = [...sim.benign(t, 120_000), ...sim.attack("tls_c2", t + 30_000).packets].sort((a, b) => a.ts - b.ts);
    const alerts: Alert[] = [];
    const sensor = new Sensor({ model: trainBaseline({ seed: 5, minutes: 3 }), rules: null, onAlert: (a, isNew) => isNew && alerts.push(a) });
    for (const p of pk) sensor.ingest(p);
    const tls = alerts.filter((a) => a.type === "tls_fingerprint");
    expect(tls.length).toBeGreaterThan(0);
    expect(new Set(tls.map((a) => a.src)).size).toBe(1);
    expect(tls[0].evidence.alpn).toBe("(none)");
  });
});
