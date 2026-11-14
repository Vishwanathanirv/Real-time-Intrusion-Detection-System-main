import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import Fastify, { type FastifyInstance } from "fastify";
import helmet from "@fastify/helmet";
import multipart from "@fastify/multipart";
import rateLimit from "@fastify/rate-limit";
import fastifyStatic from "@fastify/static";
import websocket from "@fastify/websocket";
import { z } from "zod";
import { ATTACKS, ATTACK_LABELS, DEFAULT_CONFIG, NetworkSimulator, PcapStreamReader, Sensor, compileRules, tlsInventory, trainBaseline, writePcap, type Alert, type DetectorConfig } from "@packeteye/core";
import { LiveSensor, type Mode } from "./live";
import { TelegramNotifier } from "./notify";
import { AlertStore } from "./store";

const here = dirname(fileURLToPath(import.meta.url));

export type AppOptions = { dbFile?: string; mode?: Mode; iface?: string; autopilot?: boolean; adminToken?: string; logger?: boolean; start?: boolean; notifier?: TelegramNotifier };

function loadEvaluation() {
  const p = [resolve(process.cwd(), "reports/evaluation.json"), resolve(here, "../../../reports/evaluation.json")].find((f) => existsSync(f));
  return p ? JSON.parse(readFileSync(p, "utf8")) : null;
}

export async function buildApp(opts: AppOptions = {}): Promise<{ app: FastifyInstance; live: LiveSensor; store: AlertStore }> {
  const config: DetectorConfig = structuredClone(DEFAULT_CONFIG);
  const store = new AlertStore(opts.dbFile);
  const live = new LiveSensor(config, { mode: opts.mode ?? (process.env.CAPTURE_INTERFACE ? "capture" : "simulator"), iface: opts.iface ?? process.env.CAPTURE_INTERFACE, autopilot: opts.autopilot });
  const notifier = opts.notifier ?? new TelegramNotifier();
  const adminToken = opts.adminToken ?? process.env.ADMIN_TOKEN;
  const evaluation = loadEvaluation();
  const baseline = trainBaseline({ seed: 99, minutes: 8 });

  const app = Fastify({ logger: opts.logger ?? false, trustProxy: true, bodyLimit: 1024 * 1024 });
  await app.register(helmet, { contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", "data:"], connectSrc: ["'self'", "ws:", "wss:"] } } });
  await app.register(rateLimit, { max: 600, timeWindow: "1 minute" });
  await app.register(multipart, { limits: { fileSize: 50 * 1024 * 1024, files: 1 } });
  await app.register(websocket);

  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof z.ZodError) return reply.status(400).send({ error: err.issues.map((i) => `${i.path.join(".") || "body"}: ${i.message}`).join("; ") });
    const status = (err as { statusCode?: number }).statusCode ?? 500;
    if (status >= 500) app.log.error(err);
    return reply.status(status).send({ error: status >= 500 ? "Internal error" : (err as Error).message });
  });

  const requireAdmin = (h: string | undefined) => {
    if (adminToken && h !== `Bearer ${adminToken}`) throw Object.assign(new Error("Admin token required"), { statusCode: 401 });
  };

  // Live alerts: persist, notify, broadcast.
  const sockets = new Set<{ send: (s: string) => void; readyState: number }>();
  const broadcast = (type: string, data: unknown) => {
    const msg = JSON.stringify({ type, data });
    for (const s of sockets) if (s.readyState === 1) s.send(msg);
  };
  // New alerts are saved at once; repeat hits of the same alert are coalesced to one write per second.
  const dirty = new Map<string, Alert>();
  live.on("alert", (a: Alert, isNew: boolean) => {
    if (isNew) {
      dirty.delete(a.id);
      broadcast("alert", store.upsert(a, "live"));
      void notifier.send(a);
    } else dirty.set(a.id, a);
  });
  const flusher = setInterval(() => {
    for (const a of dirty.values()) broadcast("alert-update", store.upsert(a, "live"));
    dirty.clear();
  }, 1000);
  live.on("stats", (s) => broadcast("stats", { ...s, state: live.state, avgMicrosPerPacket: +(live.sensor.avgNsPerPacket / 1000).toFixed(2) }));
  live.on("attack", (a) => broadcast("attack", a));
  live.on("error", (e: Error) => app.log.error(e.message));

  app.get("/api/health", async () => ({ ok: true, mode: live.state.mode, running: live.state.running, notifications: notifier.enabled }));

  app.get("/api/ws", { websocket: true }, (socket) => {
    sockets.add(socket);
    socket.send(JSON.stringify({ type: "hello", data: { state: live.state, stats: live.sensor.stats() } }));
    socket.on("close", () => sockets.delete(socket));
  });

  app.get("/api/stats", async () => ({ ...live.sensor.stats(), state: live.state, avgMicrosPerPacket: +(live.sensor.avgNsPerPacket / 1000).toFixed(2), alerts: store.summary(Date.now() - 24 * 3600_000) }));

  app.get("/api/alerts", async (req) => {
    const q = z.object({ status: z.enum(["open", "acknowledged", "resolved"]).optional(), severity: z.enum(["low", "medium", "high", "critical"]).optional(), type: z.string().max(32).optional(), limit: z.coerce.number().int().min(1).max(500).default(100) }).parse(req.query);
    return { alerts: store.list(q) };
  });

  app.get("/api/alerts/:id", async (req, reply) => {
    const a = store.get((req.params as { id: string }).id);
    return a ? { alert: a } : reply.status(404).send({ error: "Not found" });
  });

  app.patch("/api/alerts/:id", async (req, reply) => {
    const body = z.object({ status: z.enum(["open", "acknowledged", "resolved"]), note: z.string().max(500).optional() }).parse(req.body);
    const a = store.setStatus((req.params as { id: string }).id, body.status, body.note);
    return a ? { alert: a } : reply.status(404).send({ error: "Not found" });
  });

  app.get("/api/attacks", async () => ({ attacks: ATTACKS.map((k) => ({ kind: k, label: ATTACK_LABELS[k] })), active: live.state.activeAttacks }));

  app.post("/api/attacks", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (req) => {
    requireAdmin(req.headers.authorization);
    const { kind } = z.object({ kind: z.enum(ATTACKS as [string, ...string[]]) }).parse(req.body);
    return { attack: live.launch(kind as (typeof ATTACKS)[number]) };
  });

  app.put("/api/live", async (req) => {
    requireAdmin(req.headers.authorization);
    const b = z.object({ autopilot: z.boolean().optional(), running: z.boolean().optional() }).parse(req.body);
    if (b.autopilot !== undefined) live.setAutopilot(b.autopilot);
    if (b.running === false) live.stop();
    if (b.running === true) live.start();
    return { state: live.state };
  });

  app.get("/api/config", async () => ({ config }));
  app.put("/api/config", async (req) => {
    requireAdmin(req.headers.authorization);
    const positive = z.number().positive();
    const patch = z
      .object({
        portScan: z.object({ distinctPorts: positive.int() }).partial(),
        hostSweep: z.object({ distinctHosts: positive.int() }).partial(),
        synFlood: z.object({ synPerSec: positive, halfOpenRatio: z.number().min(0).max(1) }).partial(),
        bruteForce: z.object({ attempts: positive.int() }).partial(),
        dnsTunnel: z.object({ entropy: positive, labelLength: positive.int() }).partial(),
        beacon: z.object({ maxJitter: z.number().min(0).max(1), minConnections: positive.int() }).partial(),
        anomaly: z.object({ threshold: z.number().min(0.5).max(0.99) }).partial(),
      })
      .partial()
      .parse(req.body);
    for (const [k, v] of Object.entries(patch)) Object.assign(config[k as keyof DetectorConfig] as object, v);
    return { config };
  });

  // ---------- detection rules (Suricata syntax) ----------
  const ruleView = () => {
    const engine = live.sensor.engine;
    return { text: live.rulesText, rules: engine.rules.map((r) => ({ sid: r.sid, rev: r.rev, msg: r.msg, proto: r.proto, classtype: r.classtype ?? null, severity: r.severity, mitre: r.mitre?.id ?? null, line: r.line, hits: engine.ruleHits.get(r.sid) ?? 0 })) };
  };
  app.get("/api/rules", async () => ruleView());
  app.put("/api/rules", { bodyLimit: 256 * 1024 }, async (req, reply) => {
    requireAdmin(req.headers.authorization);
    const { text } = z.object({ text: z.string().max(200_000) }).parse(req.body);
    const { rules, errors } = compileRules(text);
    if (errors.length) return reply.status(400).send({ error: `${errors.length} rule${errors.length > 1 ? "s" : ""} could not be loaded`, errors });
    live.rulesText = text;
    live.sensor.engine.setRules(rules);
    return ruleView();
  });

  // ---------- TLS client inventory ----------
  app.get("/api/tls", async () => ({ clients: tlsInventory(live.sensor.engine), commonHosts: config.tls.commonHosts }));

  app.get("/api/evaluation", async (_req, reply) => (evaluation ? evaluation : reply.status(404).send({ error: "Run `npm run evaluate` to generate the report." })));

  /** Offline analysis of an uploaded capture in an isolated sensor. */
  app.post("/api/pcap", { bodyLimit: 55 * 1024 * 1024, config: { rateLimit: { max: 6, timeWindow: "1 minute" } } }, async (req, reply) => {
    const file = await req.file();
    if (!file) return reply.status(400).send({ error: "Upload a .pcap file in the 'file' field." });
    const alerts = new Map<string, Alert>();
    const sensor = new Sensor({ config, model: baseline, rules: live.rulesText, onAlert: (a) => alerts.set(a.id, { ...a }) });
    let first = Infinity;
    let last = 0;
    let tick = 0;
    const reader = new PcapStreamReader((p) => {
      first = Math.min(first, p.ts);
      last = Math.max(last, p.ts);
      sensor.ingest(p);
      if (p.ts - tick > 1000) {
        sensor.tick(p.ts);
        tick = p.ts;
      }
    });
    try {
      for await (const chunk of file.file) reader.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    } catch (e) {
      return reply.status(400).send({ error: (e as Error).message });
    }
    if (file.file.truncated) return reply.status(413).send({ error: "File is larger than 50 MB." });
    sensor.flows.flush();
    const s = sensor.stats(last);
    return {
      file: file.filename,
      packets: reader.packets,
      skipped: reader.skipped,
      durationSec: reader.packets ? +((last - first) / 1000).toFixed(1) : 0,
      flows: s.flows,
      bytes: s.bytes,
      protocols: s.protocols,
      topTalkers: s.topTalkers,
      topPorts: s.topPorts,
      alerts: [...alerts.values()].sort((a, b) => a.firstSeen - b.firstSeen),
      tls: tlsInventory(sensor.engine),
    };
  });

  /** A ready-made capture with every attack type, for trying the analyser or Wireshark. */
  app.get("/api/pcap/sample", async (_req, reply) => {
    const sim = new NetworkSimulator(4242);
    const t = Date.UTC(2026, 0, 3, 10);
    const pk = sim.benign(t, 60_000);
    let at = t + 5_000;
    for (const k of ATTACKS) {
      const a = sim.attack(k, at);
      pk.push(...a.packets);
      at += 12_000;
    }
    pk.sort((a, b) => a.ts - b.ts);
    reply.header("content-type", "application/vnd.tcpdump.pcap").header("content-disposition", 'attachment; filename="packeteye-sample.pcap"');
    return Buffer.from(writePcap(pk, 128));
  });

  const webDist = [resolve(process.cwd(), "apps/web/dist"), resolve(here, "../../web/dist")].find((p) => existsSync(join(p, "index.html")));
  if (webDist) {
    await app.register(fastifyStatic, { root: webDist, wildcard: false });
    app.setNotFoundHandler((req, reply) => (req.url.startsWith("/api/") ? reply.status(404).send({ error: "Not found" }) : reply.sendFile("index.html")));
  }

  app.addHook("onClose", async () => {
    clearInterval(flusher);
    live.stop();
    store.close();
  });
  if (opts.start !== false) live.start();
  return { app, live, store };
}
