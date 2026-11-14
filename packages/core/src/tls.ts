import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

/**
 * TLS ClientHello parsing and JA4 fingerprinting (FoxIO JA4 specification).
 *
 * Encryption hides what is said, but not how a client says hello: the cipher suites,
 * extensions and signature algorithms a TLS library offers are set by the software, not
 * the user. JA4 turns them into a short, stable fingerprint, so a malware implant on a
 * workstation stands out from the browsers around it even though every byte after the
 * handshake is encrypted.
 */

export type ClientHello = {
  legacyVersion: number;
  ciphers: number[];
  extensions: number[];
  sni?: string;
  alpn: string[];
  /** Raw first ALPN value, needed for the non-alphanumeric rule. */
  alpnRaw?: Uint8Array;
  supportedVersions: number[];
  sigAlgs: number[];
  groups: number[];
};

export type TlsInfo = { ja4: string; sni?: string; alpn?: string; client?: string };

export const isGrease = (v: number) => (v & 0x0f0f) === 0x0a0a && v >> 8 === (v & 0xff);

const u16 = (b: Uint8Array, o: number) => (b[o] << 8) | b[o + 1];

export class TlsParseError extends Error {}

/** Returns true if a TCP payload starts with a TLS handshake record carrying a ClientHello. */
export const looksLikeClientHello = (b: Uint8Array, o: number, end: number) => end - o >= 6 && b[o] === 0x16 && b[o + 1] === 0x03 && b[o + 5] === 0x01;

/** Parses a ClientHello from the start of a TLS record. Throws on truncation or malformed input. */
export function parseClientHello(b: Uint8Array, start = 0, end = b.length): ClientHello {
  const need = (o: number, n: number) => {
    if (o + n > end) throw new TlsParseError("ClientHello is truncated");
  };
  need(start, 9);
  if (b[start] !== 0x16 || b[start + 5] !== 0x01) throw new TlsParseError("Not a ClientHello");
  let o = start + 9; // record header (5) + handshake type and length (4)
  need(o, 2 + 32 + 1);
  const legacyVersion = u16(b, o);
  o += 34;
  const sid = b[o];
  o += 1 + sid;
  need(o, 2);
  const cl = u16(b, o);
  o += 2;
  need(o, cl);
  const ciphers: number[] = [];
  for (let i = 0; i < cl; i += 2) ciphers.push(u16(b, o + i));
  o += cl;
  need(o, 1);
  o += 1 + b[o]; // compression methods
  const hello: ClientHello = { legacyVersion, ciphers, extensions: [], alpn: [], supportedVersions: [], sigAlgs: [], groups: [] };
  if (o + 2 > end) return hello; // no extensions (old clients)
  const extEnd = o + 2 + u16(b, o);
  o += 2;
  need(o, extEnd - o);
  while (o + 4 <= extEnd) {
    const type = u16(b, o);
    const len = u16(b, o + 2);
    const d = o + 4;
    need(d, len);
    hello.extensions.push(type);
    if (type === 0x0000 && len >= 5) {
      const n = u16(b, d + 3);
      hello.sni = new TextDecoder().decode(b.subarray(d + 5, d + 5 + n)).toLowerCase();
    } else if (type === 0x0010 && len >= 3) {
      let p = d + 2;
      while (p < d + len) {
        const n = b[p];
        const raw = b.subarray(p + 1, p + 1 + n);
        if (!hello.alpnRaw) hello.alpnRaw = raw;
        hello.alpn.push(new TextDecoder().decode(raw));
        p += 1 + n;
      }
    } else if (type === 0x002b && len >= 1) {
      for (let i = 0; i < b[d]; i += 2) hello.supportedVersions.push(u16(b, d + 1 + i));
    } else if (type === 0x000d && len >= 2) {
      const n = u16(b, d);
      for (let i = 0; i < n; i += 2) hello.sigAlgs.push(u16(b, d + 2 + i));
    } else if (type === 0x000a && len >= 2) {
      const n = u16(b, d);
      for (let i = 0; i < n; i += 2) hello.groups.push(u16(b, d + 2 + i));
    }
    o = d + len;
  }
  return hello;
}

const VERSIONS: Record<number, string> = { 0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3" };
const hex4 = (v: number) => v.toString(16).padStart(4, "0");
const hash12 = (s: string) => bytesToHex(sha256(new TextEncoder().encode(s))).slice(0, 12);
const isAlnum = (c: number) => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);

/** JA4 fingerprint of a ClientHello (TCP). Format: `t13d1516h2_8daaf6152771_e5627efa2ab1`. */
export function ja4(h: ClientHello, transport: "t" | "q" = "t"): string {
  const versions = h.supportedVersions.filter((v) => !isGrease(v));
  const version = VERSIONS[versions.length ? Math.max(...versions) : h.legacyVersion] ?? "00";
  const ciphers = h.ciphers.filter((c) => !isGrease(c));
  const exts = h.extensions.filter((e) => !isGrease(e));
  const two = (n: number) => String(Math.min(n, 99)).padStart(2, "0");
  let alpn = "00";
  const raw = h.alpnRaw;
  if (raw && raw.length) {
    const first = raw[0];
    const last = raw[raw.length - 1];
    alpn = isAlnum(first) && isAlnum(last) ? String.fromCharCode(first) + String.fromCharCode(last) : hex4(first).slice(2, 3) + hex4(last).slice(3);
  }
  const a = `${transport}${version}${h.sni ? "d" : "i"}${two(ciphers.length)}${two(exts.length)}${alpn}`;
  const b = ciphers.length ? hash12([...ciphers].sort((x, y) => x - y).map(hex4).join(",")) : "000000000000";
  const sortedExts = exts.filter((e) => e !== 0x0000 && e !== 0x0010).sort((x, y) => x - y).map(hex4).join(",");
  const sig = h.sigAlgs.filter((s) => !isGrease(s)).map(hex4).join(",");
  const c = sortedExts || sig ? hash12(sig ? `${sortedExts}_${sig}` : sortedExts) : "000000000000";
  return `${a}_${b}_${c}`;
}

// ---------- building ClientHellos (for the simulator and for tests) ----------

/** A TLS client's handshake habits. The simulator gives each host and each malware family one. */
export type ClientProfile = {
  id: string;
  label: string;
  ciphers: number[];
  extensions: number[];
  alpn: string[];
  versions: number[];
  sigAlgs: number[];
  groups: number[];
  grease?: boolean;
};

function ext(type: number, data: number[]): number[] {
  return [type >> 8, type & 0xff, data.length >> 8, data.length & 0xff, ...data];
}
const be16 = (v: number) => [v >> 8, v & 0xff];
const ascii = (s: string) => [...new TextEncoder().encode(s)];

/** Encodes a complete TLS record containing a ClientHello for `sni`. */
export function buildClientHello(p: ClientProfile, sni?: string, seed = 1): Uint8Array {
  let s = seed >>> 0 || 1;
  const rnd = () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) >>> 24) & 0xff;
  const grease = 0x0a0a + 0x1010 * (seed % 16);
  const exts: number[] = [];
  if (p.grease) exts.push(...ext(grease, []));
  for (const e of p.extensions) {
    if (e === 0x0000) {
      if (!sni) continue;
      const name = ascii(sni);
      exts.push(...ext(0, [...be16(name.length + 3), 0, ...be16(name.length), ...name]));
    } else if (e === 0x0010) {
      const list = p.alpn.flatMap((a) => [a.length, ...ascii(a)]);
      exts.push(...ext(0x0010, [...be16(list.length), ...list]));
    } else if (e === 0x002b) {
      const v = p.versions.flatMap(be16);
      exts.push(...ext(0x002b, [v.length, ...v]));
    } else if (e === 0x000d) {
      const v = p.sigAlgs.flatMap(be16);
      exts.push(...ext(0x000d, [...be16(v.length), ...v]));
    } else if (e === 0x000a) {
      const v = p.groups.flatMap(be16);
      exts.push(...ext(0x000a, [...be16(v.length), ...v]));
    } else if (e === 0x000b) exts.push(...ext(0x000b, [1, 0]));
    else exts.push(...ext(e, []));
  }
  const ciphers = [...(p.grease ? [grease] : []), ...p.ciphers].flatMap(be16);
  const body = [0x03, 0x03, ...Array.from({ length: 32 }, rnd), 32, ...Array.from({ length: 32 }, rnd), ...be16(ciphers.length), ...ciphers, 1, 0, ...be16(exts.length), ...exts];
  const hs = [0x01, body.length >> 16, (body.length >> 8) & 0xff, body.length & 0xff, ...body];
  return new Uint8Array([0x16, 0x03, 0x01, ...be16(hs.length), ...hs]);
}

const MODERN = [0x1301, 0x1302, 0x1303];
const SIGS_BROWSER = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

/**
 * Client profiles used by the simulated office. The browser profiles follow the shape of real
 * browser handshakes (the first one reproduces the example in the JA4 specification); the
 * implant profiles mimic common non-browser TLS stacks used by malware.
 */
export const CLIENT_PROFILES: ClientProfile[] = [
  {
    id: "chromium",
    label: "Chromium-based browser",
    ciphers: [...MODERN, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
    extensions: [0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x0015, 0x4469],
    alpn: ["h2", "http/1.1"],
    versions: [0x0304, 0x0303],
    sigAlgs: SIGS_BROWSER,
    groups: [0x001d, 0x0017, 0x0018],
    grease: true,
  },
  {
    id: "firefox",
    label: "Firefox",
    ciphers: [...MODERN.slice(0, 1), 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
    extensions: [0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c, 0x0015],
    alpn: ["h2", "http/1.1"],
    versions: [0x0304, 0x0303],
    sigAlgs: [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201],
    groups: [0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
  },
  {
    id: "os-update",
    label: "OS update service",
    ciphers: [0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f],
    extensions: [0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0023, 0x0010, 0x0017, 0xff01],
    alpn: ["http/1.1"],
    versions: [],
    sigAlgs: [0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603],
    groups: [0x001d, 0x0017, 0x0018],
  },
  {
    id: "implant-go",
    label: "Go TLS stack (common in implants)",
    ciphers: [...MODERN, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0xc012, 0x000a],
    extensions: [0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0xff01, 0x0012, 0x002b, 0x0033],
    alpn: [],
    versions: [0x0304, 0x0303],
    sigAlgs: [0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
    groups: [0x001d, 0x0017, 0x0018, 0x0019],
  },
  {
    id: "implant-py",
    label: "Python requests / urllib3",
    ciphers: [...MODERN, 0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f, 0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff],
    extensions: [0x0000, 0x000b, 0x000a, 0x0023, 0x0016, 0x0017, 0x000d, 0x002b, 0x002d, 0x0033],
    alpn: [],
    versions: [0x0304, 0x0303, 0x0302, 0x0301],
    sigAlgs: [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
    groups: [0x001d, 0x0017, 0x001e, 0x0019, 0x0018],
  },
];

const fingerprints = new Map<string, string>();

/** JA4 of a profile, computed by building and parsing a real ClientHello. */
export function profileJa4(p: ClientProfile): string {
  let f = fingerprints.get(p.id);
  if (!f) {
    f = ja4(parseClientHello(buildClientHello(p, "example.com")));
    fingerprints.set(p.id, f);
  }
  return f;
}

export const profileById = (id: string) => CLIENT_PROFILES.find((p) => p.id === id);

/** The cipher and extension hashes (JA4_b and JA4_c): the same whether or not a server name was sent. */
export const ja4Core = (fp: string) => fp.split("_").slice(1).join("_");

/** Names a fingerprint if its software matches a known profile. */
export function describeJa4(fp: string): string | undefined {
  const core = ja4Core(fp);
  return CLIENT_PROFILES.find((p) => ja4Core(profileJa4(p)) === core)?.label;
}
