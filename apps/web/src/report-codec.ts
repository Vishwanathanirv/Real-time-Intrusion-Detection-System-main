import type { Alert, Frame } from "./lib";

/**
 * A shareable incident report lives entirely in its link: the alert, its evidence and a few dozen
 * frames of the network around it, compressed into the URL fragment. The fragment never reaches a
 * server, so sharing a report uploads nothing.
 */
export type Report = { v: 1; createdAt: number; alert: Alert; frames: Frame[] };

const MAX_FRAMES = 36;
const MAX_EDGES = 10;

/** Keeps the frames around an incident, and in each one the incident's own links plus the busiest few. */
export function buildReport(alert: Alert, frames: readonly Frame[], now = Date.now()): Report {
  const hosts = new Set([alert.src, alert.dst].map((a) => (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(a) ? a.slice(0, a.lastIndexOf(":")) : a)));
  const from = alert.firstSeen - 8_000;
  const to = alert.lastSeen + 6_000;
  let window = frames.filter((f) => f.t >= from && f.t <= to);
  if (window.length > MAX_FRAMES) {
    const step = window.length / MAX_FRAMES;
    window = Array.from({ length: MAX_FRAMES }, (_, i) => window[Math.floor(i * step)]);
  }
  const trimmed = window.map((f) => {
    // The attacker-to-target link first, then anything else touching either host, then context.
    const both = (e: Frame["graph"]["edges"][number]) => hosts.has(e.src) && hosts.has(e.dst);
    const mine = f.graph.edges.filter((e) => hosts.has(e.src) || hosts.has(e.dst)).sort((a, b) => Number(both(b)) - Number(both(a)));
    const rest = f.graph.edges.filter((e) => !(hosts.has(e.src) || hosts.has(e.dst))).slice(0, Math.max(0, MAX_EDGES - mine.length));
    const edges = [...mine.slice(0, MAX_EDGES), ...rest];
    const keep = new Set(edges.flatMap((e) => [e.src, e.dst]));
    return { t: Math.round(f.t), packets: f.packets, bytes: f.bytes, graph: { nodes: f.graph.nodes.filter((n) => keep.has(n.ip)), edges } };
  });
  const { id, type, severity, title, description, src, dst, firstSeen, lastSeen, count, mitre, evidence, status, note } = alert;
  return { v: 1, createdAt: now, alert: { id, type, severity, title, description, src, dst, firstSeen, lastSeen, count, mitre, evidence, status, note }, frames: trimmed };
}

const toB64 = (b: Uint8Array) => {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const fromB64 = (s: string) => {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

async function pipe(data: Uint8Array, stream: CompressionStream | DecompressionStream) {
  const out = new Blob([data as Uint8Array<ArrayBuffer>]).stream().pipeThrough(stream);
  return new Uint8Array(await new Response(out).arrayBuffer());
}

export async function encodeReport(r: Report): Promise<string> {
  return toB64(await pipe(new TextEncoder().encode(JSON.stringify(r)), new CompressionStream("deflate-raw")));
}

/** Decodes a report fragment. Throws on anything that isn't a well-formed report. */
export async function decodeReport(fragment: string): Promise<Report> {
  const json = new TextDecoder().decode(await pipe(fromB64(fragment.replace(/^#/, "")), new DecompressionStream("deflate-raw")));
  const r = JSON.parse(json) as Report;
  const a = r?.alert;
  if (r?.v !== 1 || !a || typeof a.title !== "string" || typeof a.firstSeen !== "number" || !a.mitre || !Array.isArray(r.frames)) throw new Error("This link does not contain a PacketEye report.");
  return r;
}
