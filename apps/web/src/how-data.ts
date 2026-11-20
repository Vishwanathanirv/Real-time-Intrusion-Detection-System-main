import { anomalyScore, decodeFrame, DEFAULT_CONFIG, encodeFrame, FLOW_FEATURES, FlowTable, flowVector, NetworkSimulator, Sensor, trainBaseline, type Alert, type Flow, type Packet } from "@packeteye/core";

/**
 * The walkthrough's sample: one implant calling home over TLS, followed through every stage of the
 * real pipeline. Nothing here is mocked: the frame is built byte by byte, decoded by the same
 * decoder that reads pcaps, grouped by the same flow table, and judged by the same detectors.
 */
export type Trace = {
  frame: number[];
  /** Byte ranges of each header, for the hex view. */
  layers: { name: string; from: number; to: number; note: string }[];
  /** Decoded fields, each pointing at the bytes it came from. */
  fields: { k: string; v: string; from: number; to: number }[];
  packet: Packet;
  flow: Flow;
  features: { name: string; value: number }[];
  /** Isolation-forest score for the flow, and the cut-off above which it alerts. */
  score: number;
  threshold: number;
  /** Signatures loaded, and the ones this connection set off. */
  rulesLoaded: number;
  ruleHits: string[];
  alerts: Alert[];
  /** How many packets of ordinary office traffic the sample was mixed into. */
  background: number;
};

const ip = (b: number[], o: number) => b.slice(o, o + 4).join(".");

export function traceSample(seed = 5): Trace {
  // Find a seed whose implant uses the Go TLS library, so a signature also gets its chance.
  let sim = new NetworkSimulator(seed);
  const t0 = Date.UTC(2026, 0, 6, 14);
  let atk = sim.attack("tls_c2", t0 + 20_000);
  for (let s = seed + 1; !atk.packets.some((p) => p.tls?.client === "implant-go"); s++) {
    sim = new NetworkSimulator(s);
    atk = sim.attack("tls_c2", t0 + 20_000);
  }
  const hello = atk.packets.find((p) => p.tls)!;
  const bytes = encodeFrame(hello);
  const frame = [...bytes];
  const packet = decodeFrame(bytes, 1, hello.ts, bytes.length)!;
  const flags = ["FIN", "SYN", "RST", "PSH", "ACK"].filter((_, i) => frame[47] & (1 << i)).join(" + ");
  const fields = [
    { k: "Source", v: ip(frame, 26), from: 26, to: 30 },
    { k: "Destination", v: ip(frame, 30), from: 30, to: 34 },
    { k: "Protocol", v: frame[23] === 6 ? "TCP" : String(frame[23]), from: 23, to: 24 },
    { k: "Time to live", v: String(frame[22]), from: 22, to: 23 },
    { k: "Source port", v: String((frame[34] << 8) | frame[35]), from: 34, to: 36 },
    { k: "Destination port", v: String((frame[36] << 8) | frame[37]), from: 36, to: 38 },
    { k: "TCP flags", v: flags, from: 47, to: 48 },
    { k: "TLS hello", v: `${frame.length - 54} bytes, server name ${packet.tls?.sni ?? "(none)"}`, from: 54, to: frame.length },
    { k: "JA4 fingerprint", v: packet.tls?.ja4 ?? "–", from: 54, to: frame.length },
  ];
  const layers = [
    { name: "Ethernet", from: 0, to: 14, note: "Which network card sent it, and that IPv4 follows." },
    { name: "IPv4", from: 14, to: 34, note: "Who is talking to whom: the two addresses." },
    { name: "TCP", from: 34, to: 54, note: "Which door (port), and the handshake flags." },
    { name: "TLS ClientHello", from: 54, to: frame.length, note: "The encrypted session's opening line. Its shape is the fingerprint." },
  ];

  // The whole connection, grouped into one flow.
  let flow: Flow | undefined;
  const session = atk.packets.filter((p) => (p.src === hello.src && p.sport === hello.sport) || (p.dst === hello.src && p.dport === hello.sport));
  const table = new FlowTable((f) => (flow ??= f));
  for (const p of session) table.add(p);
  table.flush();
  const vector = flowVector(flow!);

  // The real sensor, on office traffic with the implant mixed in.
  const model = trainBaseline({ seed: 99, minutes: 3 });
  const alerts: Alert[] = [];
  const sensor = new Sensor({ model, onAlert: (a, isNew) => isNew && alerts.push({ ...a }) });
  const benign = sim.benign(t0, 60_000);
  const all = [...benign, ...atk.packets].sort((a, b) => a.ts - b.ts);
  let tick = t0;
  for (const p of all) {
    while (p.ts - tick >= 1000) sensor.tick((tick += 1000));
    sensor.ingest(p);
  }
  sensor.flows.flush();
  const mine = alerts.filter((a) => a.src === hello.src || a.dst.startsWith(hello.dst));
  return {
    frame,
    layers,
    fields,
    packet,
    flow: flow!,
    features: FLOW_FEATURES.map((name, i) => ({ name, value: vector[i] })),
    score: anomalyScore(model, vector),
    threshold: DEFAULT_CONFIG.anomaly.threshold,
    rulesLoaded: sensor.engine.rules.length,
    ruleHits: mine.filter((a) => a.type === "rule").map((a) => a.title),
    alerts: mine,
    background: benign.length,
  };
}
