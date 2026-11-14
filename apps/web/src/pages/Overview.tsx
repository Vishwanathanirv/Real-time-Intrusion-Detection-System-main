import { useState } from "react";
import { api, bytes, num, useLive, usePoll, type Alert } from "../lib";
import { AlertDrawer, AlertRow, Bars, Kpi, Panel, TrafficChart } from "../ui";

type AttackList = { attacks: { kind: string; label: string }[] };

export function Overview() {
  const { stats, alerts, connected, isFresh } = useLive();
  const { data: attackList } = usePoll<AttackList>("/api/attacks", 0);
  const [open, setOpen] = useState<Alert | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const last = stats?.series.slice(-5) ?? [];
  const pps = last.length ? Math.round(last.reduce((a, s) => a + s.packets, 0) / last.length) : 0;
  const bps = last.length ? last.reduce((a, s) => a + s.bytes, 0) / last.length : 0;
  const totalProto = stats ? Object.values(stats.protocols).reduce((a, b) => a + b, 0) || 1 : 1;
  const openCount = alerts.filter((a) => (a.status ?? "open") === "open").length;

  async function launch(kind: string, label: string) {
    setMsg(null);
    try {
      await api("/api/attacks", { method: "POST", json: { kind } });
      setMsg(`${label} launched. Watch the alerts panel.`);
    } catch (e) {
      setMsg((e as Error).message);
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Network overview</h1>
          <p className="mt-1 text-sm text-muted">
            {stats?.state.mode === "capture" ? "Live capture from a network interface." : "Simulated office network: 24 workstations, a web, file, database and DNS server."}
          </p>
        </div>
        <span className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs ${connected ? "bg-ok-soft text-ok" : "bg-panel-2 text-muted"}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${connected ? "animate-pulse bg-ok" : "bg-faint"}`} />
          {connected ? "Sensor online" : "Connecting…"}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Kpi label="Packets / sec" value={num(pps)} sub={stats ? `${num(stats.packets)} total` : undefined} tone="accent" />
        <Kpi label="Bandwidth" value={`${bytes(bps)}/s`} sub={stats ? `${bytes(stats.bytes)} seen` : undefined} />
        <Kpi label="Active flows" value={stats ? num(stats.activeFlows) : "–"} sub={stats ? `${num(stats.flows)} completed` : undefined} />
        <Kpi label="Open alerts" value={openCount} sub={`${alerts.filter((a) => a.severity === "critical" || a.severity === "high").length} high or critical`} tone={openCount ? "bad" : "ok"} />
        <Kpi label="Cost per packet" value={stats?.avgMicrosPerPacket ? `${stats.avgMicrosPerPacket} µs` : "–"} sub="decode → flow → 7 detectors" />
      </div>

      <div className="grid gap-5 lg:grid-cols-[1.6fr_1fr]">
        <Panel title="Traffic, last 2 minutes" action={<span className="flex items-center gap-1.5 text-xs text-muted"><span className="h-2.5 w-0.5 bg-bad" /> alert fired</span>}>
          <div className="px-4 py-3">{stats ? <TrafficChart series={stats.series} /> : <div className="h-36" />}</div>
        </Panel>
        <Panel title="Simulate an attack" action={<span className="text-xs text-muted">{stats?.state.activeAttacks.length ? `${stats.state.activeAttacks.length} running` : stats?.state.autopilot ? "autopilot on" : ""}</span>}>
          <div className="grid grid-cols-2 gap-2 p-4">
            {(attackList?.attacks ?? []).map((a) => (
              <button key={a.kind} className="btn justify-start" disabled={stats?.state.mode !== "simulator"} onClick={() => launch(a.kind, a.label)}>
                {a.label}
              </button>
            ))}
          </div>
          {msg && <p className="px-4 pb-4 text-xs text-muted">{msg}</p>}
        </Panel>
      </div>

      <div className="grid gap-5 lg:grid-cols-[1.6fr_1fr]">
        <Panel title="Latest alerts" action={<a href="/alerts" className="text-xs text-muted hover:text-ink">All alerts →</a>}>
          {alerts.length ? (
            <ul>
              {alerts.slice(0, 9).map((a) => (
                <AlertRow key={a.id} a={a} fresh={isFresh(a.id)} onOpen={setOpen} />
              ))}
            </ul>
          ) : (
            <p className="px-4 py-10 text-center text-sm text-muted">No alerts yet. Launch an attack to see detection in action.</p>
          )}
        </Panel>
        <div className="space-y-5">
          <Panel title="Top talkers">
            <div className="p-4">
              <Bars rows={(stats?.topTalkers ?? []).slice(0, 6).map((t) => ({ label: t.ip, value: t.bytes, hint: bytes(t.bytes) }))} />
            </div>
          </Panel>
          <Panel title="Protocols and ports">
            <div className="space-y-4 p-4">
              <div className="flex h-2.5 overflow-hidden rounded-full bg-panel-2">
                {stats &&
                  (["tcp", "udp", "icmp"] as const).map((p, i) => (
                    <div key={p} style={{ width: `${(stats.protocols[p] / totalProto) * 100}%`, background: ["var(--accent)", "var(--warn)", "var(--ok)"][i] }} />
                  ))}
              </div>
              <div className="flex gap-4 text-xs text-muted">
                {stats &&
                  (["tcp", "udp", "icmp"] as const).map((p, i) => (
                    <span key={p} className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-sm" style={{ background: ["var(--accent)", "var(--warn)", "var(--ok)"][i] }} />
                      {p.toUpperCase()} {Math.round((stats.protocols[p] / totalProto) * 100)}%
                    </span>
                  ))}
              </div>
              <Bars rows={(stats?.topPorts ?? []).slice(0, 5).map((p) => ({ label: `:${p.port}`, value: p.packets, hint: num(p.packets) }))} />
            </div>
          </Panel>
        </div>
      </div>
      {open && <AlertDrawer alert={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
