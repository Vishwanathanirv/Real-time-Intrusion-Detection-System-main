/**
 * The page's side of the demo sensor: the same calls the server API offers, carried to a Web Worker
 * that runs the sensor (see worker.ts).
 */
type Message = { type: string; data: unknown };
type Listener = (m: Message) => void;

const worker = new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
const pending = new Map<number, { ok: (v: unknown) => void; fail: (e: Error) => void }>();
const listeners = new Set<Listener>();
let seq = 0;
let listening = false;

worker.onmessage = (e: MessageEvent<{ id?: number; result?: unknown; error?: string; event?: Message }>) => {
  const m = e.data;
  if (m.event) {
    for (const l of listeners) l(m.event);
    return;
  }
  const p = pending.get(m.id!);
  if (!p) return;
  pending.delete(m.id!);
  if (m.error !== undefined) p.fail(new Error(m.error));
  else p.ok(m.result);
};

function call<T>(msg: Record<string, unknown>): Promise<T> {
  const id = ++seq;
  return new Promise<T>((ok, fail) => {
    pending.set(id, { ok: ok as (v: unknown) => void, fail });
    worker.postMessage({ ...msg, id });
  });
}

export const demo = {
  handle: (method: string, path: string, body?: unknown) => call<{ status: number; data: unknown }>({ op: "handle", method, path, body }),
  analyze: <T>(file: File) => call<T>({ op: "analyze", file }),
  samplePcap: () => call<Blob>({ op: "sample" }),
  async subscribe(l: Listener): Promise<() => void> {
    if (!listening) {
      listening = true;
      void call({ op: "listen" });
    }
    const hello = await call<unknown>({ op: "hello" });
    listeners.add(l);
    l({ type: "hello", data: hello });
    return () => void listeners.delete(l);
  },
};
