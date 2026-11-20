import { DemoSensor } from "./server";

/** The demo sensor's thread: requests come in as messages, events and replies go back the same way. */
const sensor = new DemoSensor();
const post = (m: unknown) => (self as unknown as Worker).postMessage(m);
let listening = false;

type Req = { id: number; op: "handle"; method: string; path: string; body?: unknown } | { id: number; op: "analyze"; file: File } | { id: number; op: "sample" } | { id: number; op: "hello" } | { id: number; op: "listen" };

self.onmessage = async (e: MessageEvent<Req>) => {
  const r = e.data;
  try {
    let result: unknown;
    if (r.op === "handle") result = await sensor.handle(r.method, r.path, r.body);
    else if (r.op === "analyze") result = await sensor.analyze(r.file);
    else if (r.op === "sample") result = sensor.samplePcap();
    else if (r.op === "hello") {
      await sensor.ready;
      result = { state: sensor.state, stats: sensor.sensor.stats() };
    } else if (r.op === "listen" && !listening) {
      listening = true;
      await sensor.subscribe((m) => m.type !== "hello" && post({ event: m }));
    }
    post({ id: r.id, result });
  } catch (err) {
    post({ id: r.id, error: (err as Error).message });
  }
};
