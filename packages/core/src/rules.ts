import { TCP, type Mitre, type Packet, type Severity } from "./types";

/**
 * A Suricata-compatible subset of the rule language, so detections can be written the way
 * SOC teams already write them:
 *
 *   alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Implant TLS client"; ja4.hash;
 *     content:"t13d190900_"; startswith; sid:1000001; rev:1; metadata:mitre_technique_id T1573;)
 *
 * Supported: actions alert/drop/reject (all raise alerts here), protocols ip/tcp/udp/icmp/dns/tls,
 * address and port variables, CIDRs, lists, ranges and negation, `->` and `<>`; options msg, sid,
 * rev, classtype, priority, metadata, reference, flags, dsize, ttl, the sticky buffers dns.query,
 * tls.sni and ja4.hash with content (nocase, startswith, endswith) and pcre, threshold and
 * detection_filter. The sensor keeps headers rather than full payloads, so content matching is
 * only allowed on those buffers; anything unsupported is reported with its line number instead
 * of being silently ignored.
 */

export type RuleVars = Record<string, string>;

export const DEFAULT_VARS: RuleVars = {
  HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]",
  EXTERNAL_NET: "!$HOME_NET",
  SSH_PORTS: "22",
  HTTP_PORTS: "[80,8080]",
};

type AddrMatch = (ip: string) => boolean;
type PortMatch = (p: number) => boolean;
type Buffer = "dns.query" | "tls.sni" | "ja4.hash";
type Check = { buffer: Buffer; test: (s: string) => boolean; describe: string };
type Limit = { kind: "limit" | "threshold" | "both" | "filter"; track: "by_src" | "by_dst"; count: number; seconds: number };

export type CompiledRule = {
  sid: number;
  rev: number;
  msg: string;
  action: string;
  proto: string;
  classtype?: string;
  severity: Severity;
  mitre?: Mitre;
  text: string;
  line: number;
  match: (p: Packet) => string | null;
  limit?: Limit;
};

export type RuleError = { line: number; message: string };

const ipToInt = (ip: string) => ip.split(".").reduce((a, o) => (a << 8) + (Number(o) & 255), 0) >>> 0;

function splitList(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const c of s) {
    if (c === "[") depth++;
    if (c === "]") depth--;
    if (c === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
    } else cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function resolve(token: string, vars: RuleVars, seen = new Set<string>()): string {
  return token.replace(/\$([A-Z_]+)/g, (_, name: string) => {
    if (seen.has(name)) throw new Error(`variable $${name} refers to itself`);
    const v = vars[name];
    if (v === undefined) throw new Error(`unknown variable $${name}`);
    return resolve(v, vars, new Set([...seen, name]));
  });
}

function addr(spec: string, vars: RuleVars): AddrMatch {
  spec = resolve(spec.trim(), vars);
  if (spec === "any") return () => true;
  if (spec.startsWith("!")) {
    const inner = addr(spec.slice(1), vars);
    return (ip) => !inner(ip);
  }
  if (spec.startsWith("[") && spec.endsWith("]")) {
    const parts = splitList(spec.slice(1, -1)).map((p) => ({ neg: p.startsWith("!"), m: addr(p.replace(/^!/, ""), vars) }));
    const pos = parts.filter((p) => !p.neg);
    const neg = parts.filter((p) => p.neg);
    return (ip) => (pos.length ? pos.some((p) => p.m(ip)) : true) && !neg.some((p) => p.m(ip));
  }
  const m = spec.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
  if (!m || m[1].split(".").some((o) => Number(o) > 255)) throw new Error(`bad address "${spec}"`);
  const bits = m[2] === undefined ? 32 : Number(m[2]);
  if (bits > 32) throw new Error(`bad prefix length in "${spec}"`);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  const net = ipToInt(m[1]) & mask;
  return (ip) => ip.includes(".") && ((ipToInt(ip) & mask) >>> 0) === net >>> 0;
}

function port(spec: string, vars: RuleVars): PortMatch {
  spec = resolve(spec.trim(), vars);
  if (spec === "any") return () => true;
  if (spec.startsWith("!")) {
    const inner = port(spec.slice(1), vars);
    return (p) => !inner(p);
  }
  if (spec.startsWith("[") && spec.endsWith("]")) {
    const parts = splitList(spec.slice(1, -1)).map((p) => ({ neg: p.startsWith("!"), m: port(p.replace(/^!/, ""), vars) }));
    const pos = parts.filter((p) => !p.neg);
    const neg = parts.filter((p) => p.neg);
    return (n) => (pos.length ? pos.some((p) => p.m(n)) : true) && !neg.some((p) => p.m(n));
  }
  const range = spec.match(/^(\d*):(\d*)$/);
  if (range) {
    const lo = range[1] ? Number(range[1]) : 0;
    const hi = range[2] ? Number(range[2]) : 65535;
    return (p) => p >= lo && p <= hi;
  }
  if (!/^\d+$/.test(spec) || Number(spec) > 65535) throw new Error(`bad port "${spec}"`);
  const n = Number(spec);
  return (p) => p === n;
}

/** Splits the option block on semicolons outside quotes, honouring \" and \; escapes. */
function splitOptions(s: string): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\" && i + 1 < s.length) {
      cur += c + s[++i];
      continue;
    }
    if (c === '"') quoted = !quoted;
    if (c === ";" && !quoted) {
      if (cur.trim()) out.push(kv(cur.trim()));
      cur = "";
    } else cur += c;
  }
  if (quoted) throw new Error("unterminated quote in options");
  if (cur.trim()) out.push(kv(cur.trim()));
  return out;
}

function kv(s: string) {
  const i = s.indexOf(":");
  return i < 0 ? { key: s.trim(), value: "" } : { key: s.slice(0, i).trim(), value: s.slice(i + 1).trim() };
}

const unquote = (v: string) => {
  const m = v.match(/^"([\s\S]*)"$/);
  if (!m) throw new Error(`expected a quoted string, got ${v}`);
  return m[1].replace(/\\(["\\;:])/g, "$1");
};

function cmp(spec: string, what: string): (n: number) => boolean {
  const m = spec.replace(/\s/g, "").match(/^(<|>|<=|>=|!)?(\d+)(?:<>(\d+))?$/);
  if (!m) throw new Error(`bad ${what} "${spec}"`);
  const a = Number(m[2]);
  if (m[3] !== undefined) return (n) => n > a && n < Number(m[3]);
  switch (m[1]) {
    case "<":
      return (n) => n < a;
    case ">":
      return (n) => n > a;
    case "<=":
      return (n) => n <= a;
    case ">=":
      return (n) => n >= a;
    case "!":
      return (n) => n !== a;
    default:
      return (n) => n === a;
  }
}

const FLAG_BITS: Record<string, number> = { F: TCP.FIN, S: TCP.SYN, R: TCP.RST, P: TCP.PSH, A: TCP.ACK, U: 0x20 };
const SEVERITY_BY_PRIORITY: Record<number, Severity> = { 1: "high", 2: "medium", 3: "low", 4: "low" };

function flagsMatcher(spec: string): (p: Packet) => boolean {
  const [main] = spec.split(",");
  const mod = main.match(/[+*!]/)?.[0];
  let mask = 0;
  for (const ch of main.replace(/[+*!0]/g, "").toUpperCase()) {
    if (!(ch in FLAG_BITS)) throw new Error(`unsupported TCP flag "${ch}"`);
    mask |= FLAG_BITS[ch];
  }
  return (p) => {
    if (p.proto !== "tcp") return false;
    const f = p.flags & 0x3f;
    if (mod === "+") return (f & mask) === mask;
    if (mod === "*") return (f & mask) !== 0;
    if (mod === "!") return (f & mask) === 0;
    return f === mask;
  };
}

function limitFrom(value: string, kind: Limit["kind"] | null): Limit {
  const o: Record<string, string> = {};
  for (const part of value.split(",")) {
    const [k, ...v] = part.trim().split(/\s+/);
    o[k] = v.join(" ");
  }
  const type = (kind ?? o.type) as Limit["kind"];
  if (!["limit", "threshold", "both", "filter"].includes(type)) throw new Error(`threshold type must be limit, threshold or both`);
  if (o.track !== "by_src" && o.track !== "by_dst") throw new Error("track must be by_src or by_dst");
  const count = Number(o.count);
  const seconds = Number(o.seconds);
  if (!(count >= 1) || !(seconds >= 1)) throw new Error("count and seconds must be positive numbers");
  return { kind: type, track: o.track, count, seconds };
}

function compileOne(text: string, line: number, vars: RuleVars): CompiledRule {
  const m = text.match(/^(\w+)\s+(\w+)\s+(.+?)\s+(\S+)\s+(->|<>)\s+(.+?)\s+(\S+)\s*\(([\s\S]*)\)\s*$/);
  if (!m) throw new Error("expected: action proto src sport -> dst dport (options)");
  const [, action, protoRaw, srcS, sportS, dir, dstS, dportS, optS] = m;
  if (!["alert", "drop", "reject", "pass"].includes(action)) throw new Error(`unknown action "${action}"`);
  const proto = protoRaw.toLowerCase();
  if (!["ip", "tcp", "udp", "icmp", "dns", "tls"].includes(proto)) throw new Error(`unsupported protocol "${protoRaw}"`);
  const src = addr(srcS, vars);
  const dst = addr(dstS, vars);
  const sport = port(sportS, vars);
  const dport = port(dportS, vars);

  let sid = 0;
  let rev = 1;
  let msg = "";
  let classtype: string | undefined;
  let priority = 2;
  let mitre: Mitre | undefined;
  let limit: Limit | undefined;
  const header: ((p: Packet) => boolean)[] = [];
  const checks: Check[] = [];
  let buffer: Buffer | null = null;
  type Content = { needle: string; nocase: boolean; starts: boolean; ends: boolean; buffer: Buffer };
  const contents: Content[] = [];
  // Modifiers (nocase, startswith, endswith) apply to the most recent content.
  const current = (): Content | undefined => contents[contents.length - 1];
  let afterContent = false;

  for (const { key, value } of splitOptions(optS)) {
    switch (key) {
      case "msg":
        msg = unquote(value);
        break;
      case "sid":
        sid = Number(value);
        if (!Number.isInteger(sid) || sid <= 0) throw new Error("sid must be a positive integer");
        break;
      case "rev":
        rev = Number(value) || 1;
        break;
      case "classtype":
        classtype = value;
        break;
      case "priority":
        priority = Number(value) || 2;
        break;
      case "reference":
        break;
      case "metadata": {
        for (const part of value.split(",")) {
          const [k, ...v] = part.trim().split(/\s+/);
          if (k === "mitre_technique_id") mitre = { id: v.join(" "), name: mitre?.name ?? "", tactic: mitre?.tactic ?? "Detection rule" };
          if (k === "mitre_technique_name") mitre = { id: mitre?.id ?? "-", name: v.join(" ").replace(/_/g, " "), tactic: mitre?.tactic ?? "Detection rule" };
          if (k === "mitre_tactic_name") mitre = { id: mitre?.id ?? "-", name: mitre?.name ?? "", tactic: v.join(" ").replace(/_/g, " ") };
        }
        break;
      }
      case "flags":
        header.push(flagsMatcher(value));
        break;
      case "dsize": {
        const c = cmp(value, "dsize");
        header.push((p) => c(p.payloadLen));
        break;
      }
      case "ttl": {
        const c = cmp(value, "ttl");
        header.push((p) => c(p.ttl));
        break;
      }
      case "dns.query":
      case "tls.sni":
      case "ja4.hash":
        afterContent = false;
        buffer = key;
        break;
      case "content": {
        if (!buffer) throw new Error("content needs a sticky buffer first (dns.query, tls.sni or ja4.hash): payloads are not kept");
        if (value.startsWith("!")) throw new Error("negated content is not supported");
        const needle = unquote(value);
        if (/\|[0-9a-fA-F ]+\|/.test(needle)) throw new Error("hex content (|..|) is not supported on text buffers");
        contents.push({ needle, nocase: false, starts: false, ends: false, buffer });
        afterContent = true;
        break;
      }
      case "nocase":
      case "startswith":
      case "endswith":
        if (!afterContent || !current()) throw new Error(`${key} must follow a content`);
        if (key === "nocase") current()!.nocase = true;
        if (key === "startswith") current()!.starts = true;
        if (key === "endswith") current()!.ends = true;
        break;
      case "pcre": {
        afterContent = false;
        if (!buffer) throw new Error("pcre needs a sticky buffer first (dns.query, tls.sni or ja4.hash)");
        const pm = unquote(value).match(/^\/([\s\S]*)\/([a-zA-Z]*)$/);
        if (!pm) throw new Error("pcre must look like \"/pattern/flags\"");
        const flags = pm[2].replace(/[^ims]/g, "");
        const re = new RegExp(pm[1], flags);
        const b = buffer;
        checks.push({ buffer: b, test: (s) => re.test(s), describe: `pcre ${pm[0]}` });
        break;
      }
      case "threshold":
        limit = limitFrom(value, null);
        break;
      case "detection_filter":
        limit = limitFrom(value, "filter");
        break;
      default:
        throw new Error(`unsupported keyword "${key}"`);
    }
  }
  for (const c of contents) {
    const { needle, nocase, starts, ends, buffer: b } = c;
    const n = nocase ? needle.toLowerCase() : needle;
    checks.push({
      buffer: b,
      describe: `content "${needle}"`,
      test: (s) => {
        const h = nocase ? s.toLowerCase() : s;
        if (starts && ends) return h === n;
        if (starts) return h.startsWith(n);
        if (ends) return h.endsWith(n);
        return h.includes(n);
      },
    });
  }
  if (!sid) throw new Error("every rule needs a sid");
  if (!msg) throw new Error("every rule needs a msg");

  const protoOk = (p: Packet) => {
    switch (proto) {
      case "ip":
        return true;
      case "dns":
        return p.proto === "udp" && p.dnsQuery !== undefined;
      case "tls":
        return p.proto === "tcp" && p.tls !== undefined;
      default:
        return p.proto === proto;
    }
  };
  const forward = (p: Packet) => src(p.src) && sport(p.sport) && dst(p.dst) && dport(p.dport);
  const reverse = (p: Packet) => src(p.dst) && sport(p.dport) && dst(p.src) && dport(p.sport);
  const value = (p: Packet, b: Buffer) => (b === "dns.query" ? p.dnsQuery : b === "tls.sni" ? p.tls?.sni : p.tls?.ja4);

  return {
    sid,
    rev,
    msg,
    action,
    proto,
    classtype,
    severity: SEVERITY_BY_PRIORITY[priority] ?? "medium",
    mitre,
    text,
    line,
    limit,
    match: (p) => {
      if (action === "pass" || !protoOk(p)) return null;
      if (!forward(p) && !(dir === "<>" && reverse(p))) return null;
      for (const h of header) if (!h(p)) return null;
      let matched = "";
      for (const c of checks) {
        const v = value(p, c.buffer);
        if (v === undefined || !c.test(v)) return null;
        matched = `${c.buffer}: ${v}`;
      }
      return matched || `${p.proto} ${p.src}:${p.sport} → ${p.dst}:${p.dport}`;
    },
  };
}

/** Parses a rules file. Rules can span lines with a trailing backslash; # starts a comment. */
export function compileRules(text: string, vars: RuleVars = DEFAULT_VARS): { rules: CompiledRule[]; errors: RuleError[] } {
  const rules: CompiledRule[] = [];
  const errors: RuleError[] = [];
  const lines = text.split(/\r?\n/);
  const sids = new Map<number, number>();
  for (let i = 0; i < lines.length; i++) {
    const start = i;
    let l = lines[i];
    while (l.trimEnd().endsWith("\\") && i + 1 < lines.length) l = l.trimEnd().slice(0, -1) + " " + lines[++i].trim();
    const t = l.trim();
    if (!t || t.startsWith("#")) continue;
    try {
      const r = compileOne(t, start + 1, vars);
      if (sids.has(r.sid)) throw new Error(`duplicate sid ${r.sid} (first used on line ${sids.get(r.sid)})`);
      sids.set(r.sid, start + 1);
      rules.push(r);
    } catch (e) {
      errors.push({ line: start + 1, message: (e as Error).message });
    }
  }
  return { rules, errors };
}

/** Applies threshold / detection_filter semantics. Returns true when the match should alert. */
export class RuleLimiter {
  private hits = new Map<string, number[]>();
  private fired = new Map<string, number>();

  allow(r: CompiledRule, p: Packet): boolean {
    const l = r.limit;
    if (!l) return true;
    const key = `${r.sid}|${l.track === "by_src" ? p.src : p.dst}`;
    const horizon = p.ts - l.seconds * 1000;
    const arr = (this.hits.get(key) ?? []).filter((t) => t > horizon);
    arr.push(p.ts);
    this.hits.set(key, arr);
    switch (l.kind) {
      case "limit": {
        const fired = arr.length <= l.count;
        return fired;
      }
      case "threshold":
        if (arr.length >= l.count) {
          this.hits.set(key, []);
          return true;
        }
        return false;
      case "both": {
        const last = this.fired.get(key) ?? -Infinity;
        if (arr.length >= l.count && p.ts - last > l.seconds * 1000) {
          this.fired.set(key, p.ts);
          return true;
        }
        return false;
      }
      case "filter":
        return arr.length > l.count;
    }
  }

  prune(now: number) {
    for (const [k, arr] of this.hits) if (!arr.length || now - arr[arr.length - 1] > 3_600_000) this.hits.delete(k);
  }
}
