import { useCallback, useEffect, useRef, useState } from "react";

export type Severity = "low" | "medium" | "high" | "critical";
export type Alert = {
  id: string;
  type: string;
  severity: Severity;
  title: string;
  description: string;
  src: string;
  dst: string;
  firstSeen: number;
  lastSeen: number;
  count: number;
  mitre: { id: string; name: string; tactic: string };
  evidence: Record<string, number | string>;
  status?: "open" | "acknowledged" | "resolved";
  note?: string | null;
};

export type Stats = {
  packets: number;
  bytes: number;
  flows: number;
  activeFlows: number;
  protocols: Record<string, number>;
  topTalkers: { ip: string; bytes: number; packets: number }[];
  topPorts: { port: number; packets: number }[];
  series: { t: number; packets: number; bytes: number; alerts: number }[];
  avgMicrosPerPacket?: number;
  state: { mode: string; running: boolean; autopilot: boolean; activeAttacks: { id: string; kind: string; endsAt: number }[] };
};

/** True in the hosted demo build, where the sensor runs inside the browser instead of on a server. */
export const DEMO = import.meta.env.VITE_DEMO === "1";

export async function api<T>(path: string, init?: RequestInit & { json?: unknown }): Promise<T> {
  if (DEMO) {
    const { demo } = await import("./demo/server");
    const r = await demo.handle(init?.method ?? "GET", path, init?.json);
    if (r.status >= 400) throw Object.assign(new Error((r.data as { error?: string }).error ?? `Request failed (${r.status})`), { details: r.data });
    return r.data as T;
  }
  const res = await fetch(path, { ...init, headers: { ...(init?.json !== undefined ? { "content-type": "application/json" } : {}), ...init?.headers }, body: init?.json !== undefined ? JSON.stringify(init.json) : init?.body });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error((data as { error?: string }).error ?? `Request failed (${res.status})`), { details: data });
  return data as T;
}

/** WebSocket feed: live stats every second plus alerts as they fire. Reconnects automatically. */
export function useLive() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);
  const fresh = useRef(new Set<string>());

  useEffect(() => {
    let ws: WebSocket | null = null;
    let stop = false;
    let retry: ReturnType<typeof setTimeout>;
    api<{ alerts: Alert[] }>("/api/alerts?limit=30").then((r) => setAlerts(r.alerts)).catch(() => {});
    const onMessage = (m: { type: string; data: unknown }) => {
      if (m.type === "stats") setStats(m.data as Stats);
      if (m.type === "hello") {
        const d = m.data as { state: Stats["state"]; stats: Omit<Stats, "state"> };
        setStats({ ...d.stats, state: d.state });
      }
      if (m.type === "alert" || m.type === "alert-update") {
        const a = m.data as Alert;
        if (m.type === "alert") {
          fresh.current.add(a.id);
          setTimeout(() => fresh.current.delete(a.id), 2500);
        }
        setAlerts((prev) => [a, ...prev.filter((p) => p.id !== a.id)].sort((x, y) => y.lastSeen - x.lastSeen).slice(0, 30));
      }
    };
    if (DEMO) {
      let unsub: (() => void) | null = null;
      void import("./demo/server")
        .then(({ demo }) => demo.subscribe(onMessage))
        .then((u) => {
          if (stop) u();
          else {
            unsub = u;
            setConnected(true);
          }
        });
      return () => {
        stop = true;
        unsub?.();
      };
    }
    const connect = () => {
      ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/ws`);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!stop) retry = setTimeout(connect, 2000);
      };
      ws.onmessage = (e) => onMessage(JSON.parse(e.data));
    };
    connect();
    return () => {
      stop = true;
      clearTimeout(retry);
      ws?.close();
    };
  }, []);
  return { stats, alerts, connected, isFresh: (id: string) => fresh.current.has(id) };
}

export function usePoll<T>(path: string | null, ms = 5000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    if (!path) return;
    try {
      setData(await api<T>(path));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [path]);
  useEffect(() => {
    void load();
    if (!ms) return;
    const t = setInterval(load, ms);
    return () => clearInterval(t);
  }, [load, ms]);
  return { data, error, reload: load };
}

export const bytes = (n: number) => (n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n >= 1e3 ? `${(n / 1e3).toFixed(1)} KB` : `${n} B`);
export const num = (n: number) => n.toLocaleString("en-IN");
export const clock = (ts: number) => new Date(ts).toLocaleTimeString("en-IN", { hour12: false });
export const ago = (ts: number) => {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`;
};
