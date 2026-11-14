import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import { MITRE, NetworkSimulator, writePcap, type Alert } from "@packeteye/core";
import { buildApp } from "../src/app";
import type { LiveSensor } from "../src/live";
import { TelegramNotifier } from "../src/notify";

let app: FastifyInstance;
let live: LiveSensor;

beforeAll(async () => {
  ({ app, live } = await buildApp({ dbFile: ":memory:", start: false, adminToken: "t0ken", notifier: new TelegramNotifier("", "") }));
});
afterAll(() => app.close());

function multipart(name: string, bytes: Uint8Array) {
  const boundary = "----pe" + Math.random().toString(16).slice(2);
  const head = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${name}"\r\nContent-Type: application/octet-stream\r\n\r\n`);
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
  return { payload: Buffer.concat([head, Buffer.from(bytes), tail]), headers: { "content-type": `multipart/form-data; boundary=${boundary}` } };
}

describe("API", () => {
  it("is healthy and exposes detector config", async () => {
    expect((await app.inject("/api/health")).json()).toMatchObject({ ok: true, mode: "simulator" });
    expect((await app.inject("/api/config")).json().config.portScan.distinctPorts).toBeGreaterThan(0);
  });

  it("analyses an uploaded pcap and finds the attack in it", async () => {
    const sim = new NetworkSimulator(5);
    const t = Date.UTC(2026, 0, 1, 12);
    const packets = [...sim.benign(t, 20_000), ...sim.attack("port_scan", t + 2000).packets].sort((a, b) => a.ts - b.ts);
    const r = await app.inject({ method: "POST", url: "/api/pcap", ...multipart("scan.pcap", writePcap(packets)) });
    expect(r.statusCode).toBe(200);
    const body = r.json();
    expect(body.packets).toBe(packets.length);
    expect(body.alerts.map((a: Alert) => a.type)).toContain("port_scan");
  });

  it("rejects files that are not pcap", async () => {
    const r = await app.inject({ method: "POST", url: "/api/pcap", ...multipart("x.pcap", new Uint8Array(100).fill(1)) });
    expect(r.statusCode).toBe(400);
  });

  it("serves a sample capture", async () => {
    const r = await app.inject("/api/pcap/sample");
    expect(r.headers["content-type"]).toContain("pcap");
    expect(r.rawPayload.readUInt32LE(0)).toBe(0xa1b2c3d4);
  });

  it("stores live alerts and lets analysts triage them", async () => {
    live.emit("alert", { id: "x1", type: "port_scan", severity: "high", title: "Port scan", description: "test", src: "1.2.3.4", dst: "10.0.0.10", firstSeen: Date.now(), lastSeen: Date.now(), count: 1, mitre: MITRE.port_scan, evidence: { distinctPorts: 300 } } satisfies Alert, true);
    const list = (await app.inject("/api/alerts?status=open")).json().alerts;
    expect(list).toHaveLength(1);
    const patched = await app.inject({ method: "PATCH", url: `/api/alerts/${list[0].id}`, payload: { status: "resolved", note: "Known pentest" } });
    expect(patched.json().alert).toMatchObject({ status: "resolved", note: "Known pentest" });
    expect((await app.inject("/api/alerts/nope")).statusCode).toBe(404);
  });

  it("guards control endpoints with the admin token and validates input", async () => {
    expect((await app.inject({ method: "POST", url: "/api/attacks", payload: { kind: "port_scan" } })).statusCode).toBe(401);
    const auth = { authorization: "Bearer t0ken" };
    expect((await app.inject({ method: "POST", url: "/api/attacks", payload: { kind: "nuke" }, headers: auth })).statusCode).toBe(400);
    const ok = await app.inject({ method: "POST", url: "/api/attacks", payload: { kind: "syn_flood" }, headers: auth });
    expect(ok.json().attack.kind).toBe("syn_flood");
    const cfg = await app.inject({ method: "PUT", url: "/api/config", payload: { portScan: { distinctPorts: 40 } }, headers: auth });
    expect(cfg.json().config.portScan.distinctPorts).toBe(40);
  });
});

describe("Telegram notifier", () => {
  const alert = { type: "syn_flood", severity: "critical", title: "SYN flood", description: "d", src: "a", dst: "b", mitre: MITRE.syn_flood } as Alert;
  it("sends high-severity alerts once per minute per type", async () => {
    const f = vi.fn().mockResolvedValue(new Response("{}"));
    const n = new TelegramNotifier("tok", "chat", f as unknown as typeof fetch);
    expect(await n.send(alert, 1000)).toBe(true);
    expect(await n.send(alert, 2000)).toBe(false);
    expect(await n.send({ ...alert, severity: "low" }, 999_999)).toBe(false);
    expect(f).toHaveBeenCalledOnce();
    expect(String(f.mock.calls[0][0])).toContain("/bottok/sendMessage");
  });
  it("is disabled without credentials", async () => {
    expect(await new TelegramNotifier("", "").send(alert)).toBe(false);
  });
});
