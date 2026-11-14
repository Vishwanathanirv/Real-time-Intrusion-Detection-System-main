import { describe, expect, it } from "vitest";
import { CLIENT_PROFILES, TlsParseError, buildClientHello, ja4, parseClientHello, profileById, profileJa4 } from "../src/tls";

describe("JA4", () => {
  it("reproduces the example fingerprint from the JA4 specification", () => {
    const hello = parseClientHello(buildClientHello(profileById("chromium")!, "www.example.com", 7));
    expect(ja4(hello)).toBe("t13d1516h2_8daaf6152771_e5627efa2ab1");
  });

  it("ignores GREASE values and the random fields, so the fingerprint is stable", () => {
    const p = profileById("chromium")!;
    const fps = new Set([1, 2, 3, 9, 15].map((seed) => ja4(parseClientHello(buildClientHello(p, `site${seed}.example.org`, seed)))));
    expect(fps.size).toBe(1);
  });

  it("parses SNI, ALPN, versions and signature algorithms", () => {
    const h = parseClientHello(buildClientHello(profileById("firefox")!, "Mail.Example.COM"));
    expect(h.sni).toBe("mail.example.com");
    expect(h.alpn).toEqual(["h2", "http/1.1"]);
    expect(h.supportedVersions).toContain(0x0304);
    expect(h.sigAlgs[0]).toBe(0x0403);
  });

  it("marks missing SNI and ALPN, and falls back to the legacy version", () => {
    const fp = ja4(parseClientHello(buildClientHello(profileById("os-update")!)));
    expect(fp.slice(0, 4)).toBe("t12i");
    const implant = ja4(parseClientHello(buildClientHello(profileById("implant-go")!, "cdn.example.net")));
    expect(implant.slice(8, 10)).toBe("00");
  });

  it("gives every client profile a distinct fingerprint", () => {
    const fps = CLIENT_PROFILES.map(profileJa4);
    expect(new Set(fps).size).toBe(fps.length);
    for (const f of fps) expect(f).toMatch(/^t(13|12)[di]\d{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/);
  });

  it("rejects truncated or non-TLS input cleanly", () => {
    const full = buildClientHello(profileById("chromium")!, "example.com");
    expect(() => parseClientHello(full.subarray(0, 60))).toThrow(TlsParseError);
    expect(() => parseClientHello(new Uint8Array([0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54]))).toThrow(TlsParseError);
  });
});

describe("JA4 profile lookup", () => {
  it("recognises a client with or without a server name", async () => {
    const { describeJa4 } = await import("../src/tls");
    const p = profileById("implant-go")!;
    const withSni = ja4(parseClientHello(buildClientHello(p, "c2.example.net")));
    const without = ja4(parseClientHello(buildClientHello(p)));
    expect(withSni[3]).toBe("d");
    expect(without[3]).toBe("i");
    expect(describeJa4(withSni)).toBe(p.label);
    expect(describeJa4(without)).toBe(p.label);
  });
});
