import { StrictMode, useEffect, useMemo, useState, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Link, NavLink, Route, Routes, useLocation, useNavigate } from "react-router";
import "@fontsource-variable/hubot-sans/wdth.css";
import "@fontsource-variable/martian-mono";
import "./index.css";
import { api, bytes, num, useLive, usePoll, type Alert } from "./lib";
import { hostOf, NetworkMap, ROLE, type Selection } from "./map";
import { Alerts } from "./pages/Alerts";
import { Analyze } from "./pages/Analyze";
import { Detection } from "./pages/Detection";
import { Rules } from "./pages/Rules";
import { Tls } from "./pages/Tls";
import { AlertBody, Bars, SevBadge, Strip, TrafficChart } from "./ui";

/** The tool dock. Each tool opens as a console over the live scope, which keeps sweeping behind it. */
const TOOLS: { to: string; t: string; icon: string }[] = [
  { to: "/", t: "Map", icon: "M3 6l6-2 6 2 6-2v14l-6 2-6-2-6 2zM9 4v14M15 6v14" },
  { to: "/alerts", t: "Alerts", icon: "M12 3l9 16H3zM12 10v4M12 17h.01" },
  { to: "/tls", t: "TLS clients", icon: "M6 11V8a6 6 0 0 1 12 0v3M5 11h14v10H5zM12 15v2" },
  { to: "/rules", t: "Rules", icon: "M5 4h14v16H5zM8 8h8M8 12h8M8 16h5" },
  { to: "/analyze", t: "Analyse a pcap", icon: "M12 3v12M7 10l5 5 5-5M4 19h16" },
  { to: "/detection", t: "Coverage", icon: "M4 20V10M10 20V4M16 20v-8M22 20H2" },
];

function Icon({ d, className = "h-[18px] w-[18px]" }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d={d} />
    </svg>
  );
}

type Live = ReturnType<typeof useLive>;

/** What the right-hand inspector shows when nothing is selected: the network right now. */
function NetworkNow({ live }: { live: Live }) {
  const s = live.stats;
  const total = s ? Object.values(s.protocols).reduce((a, b) => a + b, 0) || 1 : 1;
  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold">The network right now</h2>
        <p className="mt-1 text-sm text-muted">{s?.state.mode === "capture" ? "Live capture from a network interface." : "A simulated office: 24 workstations and five servers. Click any dot to inspect it."}</p>
      </div>
      <section>
        <h3 className="label">Busiest hosts</h3>
        <div className="mt-2">
          <Bars rows={(s?.topTalkers ?? []).slice(0, 6).map((t) => ({ label: ROLE[t.ip] ?? t.ip, value: t.bytes, hint: bytes(t.bytes) }))} />
        </div>
      </section>
      <section>
        <h3 className="label">Protocols</h3>
        <div className="mt-2 flex h-2.5 overflow-hidden rounded-full bg-panel-2">
          {s && (["tcp", "udp", "icmp"] as const).map((p, i) => <div key={p} style={{ width: `${(s.protocols[p] / total) * 100}%`, background: ["var(--accent)", "var(--muted)", "var(--warn)"][i] }} />)}
        </div>
        <div className="mt-1.5 flex gap-4 text-xs text-muted">
          {s &&
            (["tcp", "udp", "icmp"] as const).map((p) => (
              <span key={p}>
                {p.toUpperCase()} {Math.round((s.protocols[p] / total) * 100)}%
              </span>
            ))}
        </div>
      </section>
      <section>
        <h3 className="label">Busiest ports</h3>
        <div className="mt-2">
          <Bars rows={(s?.topPorts ?? []).slice(0, 5).map((p) => ({ label: `:${p.port}`, value: p.packets, hint: num(p.packets) }))} />
        </div>
      </section>
      <p className="border-t border-line pt-3 text-xs text-faint">
        For networks you own or may monitor.
      </p>
    </div>
  );
}

function HostCard({ ip, live, onAlert }: { ip: string; live: Live; onAlert: (a: Alert) => void }) {
  const g = live.stats?.graph;
  const node = g?.nodes.find((n) => n.ip === ip);
  const peers = (g?.edges ?? []).filter((e) => e.src === ip || e.dst === ip).sort((a, b) => b.bytes - a.bytes);
  const related = live.alerts.filter((a) => hostOf(a.src) === ip || hostOf(a.dst) === ip);
  const [copied, setCopied] = useState(false);
  return (
    <div className="space-y-5">
      <div>
        <div className="silk">{node?.internal === false ? "On the internet" : ROLE[ip] ? "Server" : "Workstation"}</div>
        <h2 className="lcd mt-1 text-xl font-medium">{ROLE[ip] ?? ip}</h2>
        {ROLE[ip] && <div className="lcd text-sm text-muted">{ip}</div>}
        <div className="mt-2 flex gap-2">
          <button
            className="btn h-8"
            onClick={() =>
              void navigator.clipboard?.writeText(ip).then(() => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1400);
              })
            }
          >
            {copied ? "Copied" : "Copy address"}
          </button>
        </div>
      </div>
      <section>
        <h3 className="label">Alerts involving it ({related.length})</h3>
        {related.length ? (
          <ul className="mt-2 space-y-1.5">
            {related.slice(0, 8).map((a) => (
              <li key={a.id}>
                <button className="screen flex w-full items-center gap-3 px-3 py-2 text-left hover:ring-1 hover:ring-accent/40" onClick={() => onAlert(a)}>
                  <SevBadge s={a.severity} />
                  <span className="min-w-0 flex-1 truncate text-sm">{a.title}</span>
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-1 text-sm text-muted">None. It looks normal.</p>
        )}
      </section>
      <section>
        <h3 className="label">Talking to ({peers.length})</h3>
        {peers.length ? (
          <div className="mt-2">
            <Bars rows={peers.slice(0, 8).map((e) => ({ label: `${e.src === ip ? "→" : "←"} ${ROLE[e.src === ip ? e.dst : e.src] ?? (e.src === ip ? e.dst : e.src)}`, value: e.bytes, hint: e.ports.length ? `:${e.ports.join(", :")}` : bytes(e.bytes) }))} />
          </div>
        ) : (
          <p className="mt-1 text-sm text-muted">Quiet for the last minute.</p>
        )}
      </section>
    </div>
  );
}

function Shell() {
  const live = useLive();
  const loc = useLocation();
  const navigate = useNavigate();
  const [sel, setSel] = useState<Selection>(null);
  const [inspector, setInspector] = useState(true);
  const { data: attackList } = usePoll<{ attacks: { kind: string; label: string }[] }>("/api/attacks", 0);
  const [attack, setAttack] = useState("port_scan");
  const [msg, setMsg] = useState<string | null>(null);
  const s = live.stats;
  const last = s?.series.slice(-5) ?? [];
  const pps = last.length ? Math.round(last.reduce((a, x) => a + x.packets, 0) / last.length) : 0;
  const bps = last.length ? last.reduce((a, x) => a + x.bytes, 0) / last.length : 0;
  const open = live.alerts.filter((a) => (a.status ?? "open") === "open");
  const sheet = loc.pathname !== "/";
  const tool = TOOLS.find((t) => t.to === loc.pathname) ?? TOOLS[0];

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName) || e.metaKey || e.ctrlKey) return;
      if (e.key === "Escape") {
        if (sheet) navigate("/");
        else setSel(null);
      }
      const n = Number(e.key);
      if (n >= 1 && n <= TOOLS.length) navigate(TOOLS[n - 1].to);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [sheet, navigate]);

  async function launch() {
    setMsg(null);
    try {
      await api("/api/attacks", { method: "POST", json: { kind: attack } });
      setMsg(`${attackList?.attacks.find((a) => a.kind === attack)?.label ?? "Attack"} launched. Watch the map.`);
      setTimeout(() => setMsg(null), 4000);
    } catch (e) {
      setMsg((e as Error).message);
    }
  }
  async function setLive(next: { running?: boolean; autopilot?: boolean }) {
    try {
      await api("/api/live", { method: "PUT", json: next });
    } catch (e) {
      setMsg((e as Error).message);
    }
  }
  const pick = (x: Selection) => {
    setSel(x);
    if (x) setInspector(true);
  };

  const inspectorBody = useMemo<ReactNode>(() => {
    if (sel?.kind === "alert") return <AlertBody key={sel.alert.id} alert={live.alerts.find((a) => a.id === sel.alert.id) ?? sel.alert} />;
    if (sel?.kind === "host") return <HostCard ip={sel.ip} live={live} onAlert={(a) => pick({ kind: "alert", alert: a })} />;
    return <NetworkNow live={live} />;
  }, [sel, live]);

  return (
    <div className="relative h-dvh overflow-hidden">
      <NetworkMap graph={s?.graph} alerts={live.alerts} selection={sel} onSelect={pick} />

      {/* Vital signs */}
      <div className="panel pointer-events-auto absolute left-3 top-3 w-[min(19rem,calc(100%-1.5rem))] p-3">
        <div className="flex items-center gap-2.5">
          <img src="/favicon.svg" alt="" className="h-7 w-7" />
          <Link to="/" className="display text-[1.1rem] font-bold">
            PacketEye
          </Link>
          <span className="ml-auto inline-flex items-center gap-1.5 text-xs text-muted" aria-live="polite">
            <span className={`led ${live.connected && s?.state.running !== false ? "" : "led-off"}`} aria-hidden />
            {!live.connected ? "Connecting" : s?.state.running === false ? "Paused" : "Live"}
          </span>
        </div>
        <dl className="telemetry mt-3" aria-label="Vital signs">
          {[
            ["PKT/S", num(pps)],
            ["BW/S", bytes(bps)],
            ["FLOWS", s ? num(s.activeFlows) : "–"],
            ["ALERTS", String(open.length)],
          ].map(([k, v], i) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd className="lcd" style={i === 3 && open.length ? { color: "var(--bad)" } : undefined}>
                {v}
              </dd>
            </div>
          ))}
        </dl>
      </div>

      {/* Alert feed */}
      <div className="pointer-events-none absolute left-3 top-[9.5rem] hidden w-[19rem] space-y-2 md:block">
        {live.alerts.slice(0, 5).map((a) => (
          <div key={a.id} className="panel pointer-events-auto overflow-hidden !rounded-[10px]">
            <Strip a={a} compact fresh={live.isFresh(a.id)} onOpen={(x) => pick({ kind: "alert", alert: x })} route={`${ROLE[hostOf(a.src)] ?? a.src} → ${ROLE[hostOf(a.dst)] ?? a.dst}`} />
          </div>
        ))}
        {!live.alerts.length && live.connected && <div className="panel pointer-events-auto px-3 py-2.5 text-sm text-muted">No alerts yet. Launch an attack from the bar below to see detection happen.</div>}
      </div>

      {/* Tool dock */}
      <nav className="panel absolute bottom-3 left-1/2 z-20 flex -translate-x-1/2 gap-0.5 p-1 md:bottom-auto md:top-3" aria-label="Tools">
        {TOOLS.map((t, i) => (
          <NavLink key={t.to} to={t.to} end title={`${t.t} (${i + 1})`} className={({ isActive }) => `flex items-center gap-2 rounded-[13px] px-2.5 py-2 text-[13px] font-semibold ${isActive ? "bg-accent text-[var(--accent-ink)]" : "text-muted hover:bg-panel-2 hover:text-ink"}`}>
            <Icon d={t.icon} />
            <span className="hidden 2xl:inline">{t.t}</span>
          </NavLink>
        ))}
      </nav>

      {/* Inspector */}
      {sheet ? null : inspector ? (
        <aside className="panel scroll-y absolute bottom-[8.5rem] right-3 top-3 z-10 hidden w-[23rem] p-4 md:block lg:bottom-[6.75rem]" aria-label="Inspector">
          <div className="mb-3 flex items-center justify-between">
            <span className="silk">{sel?.kind === "alert" ? "Alert" : sel?.kind === "host" ? "Host" : "Scope readout"}</span>
            <div className="flex gap-1">
              {sel && (
                <button className="btn h-7 px-2 text-xs" onClick={() => setSel(null)}>
                  Clear
                </button>
              )}
              <button className="btn h-7 px-2 text-xs" onClick={() => setInspector(false)} aria-label="Hide the inspector">
                Hide
              </button>
            </div>
          </div>
          {inspectorBody}
        </aside>
      ) : (
        <button className="panel absolute right-3 top-3 z-10 hidden px-3 py-2 text-sm font-semibold md:block" onClick={() => setInspector(true)}>
          Show inspector
        </button>
      )}
      {/* On phones the inspector is a sheet that appears when you pick something. */}
      {sel && (
        <aside className="panel rise scroll-y absolute inset-x-2 bottom-[4.5rem] z-30 max-h-[60dvh] p-4 md:hidden" aria-label="Details">
          <button className="btn absolute right-3 top-3 h-7 px-2 text-xs" onClick={() => setSel(null)}>
            Close
          </button>
          {inspectorBody}
        </aside>
      )}

      {/* Timeline and attack bar */}
      <div className="panel absolute bottom-[4.25rem] left-3 right-3 z-10 flex flex-wrap items-center gap-x-4 gap-y-2 p-2.5 md:bottom-3 md:right-[24.75rem] lg:flex-nowrap">
        <div className="min-w-0 flex-1 basis-60">
          {s ? <TrafficChart series={s.series} height={56} /> : <div className="h-14" />}
        </div>
        <div className="flex w-full flex-wrap items-center gap-2 md:w-auto md:shrink-0">
          <select className="field h-9 min-w-0 flex-1 md:w-auto md:flex-none" value={attack} onChange={(e) => setAttack(e.target.value)} aria-label="Attack to simulate" disabled={s?.state.mode !== "simulator"}>
            {(attackList?.attacks ?? []).map((a) => (
              <option key={a.kind} value={a.kind}>
                {a.label}
              </option>
            ))}
          </select>
          <button className="btn btn-accent h-9" onClick={launch} disabled={s?.state.mode !== "simulator"}>
            Launch
          </button>
          <button className="btn h-9" onClick={() => setLive({ running: !(s?.state.running ?? true) })} disabled={!s}>
            {s?.state.running === false ? "Resume" : "Pause"}
          </button>
          <label className="silk flex items-center gap-1.5">
            <input type="checkbox" checked={Boolean(s?.state.autopilot)} onChange={(e) => setLive({ autopilot: e.target.checked })} disabled={s?.state.mode !== "simulator"} className="accent-[var(--accent)]" />
            Autopilot
          </label>
        </div>
        {msg && <p className="w-full text-xs text-muted" aria-live="polite">{msg}</p>}
      </div>

      {/* A tool's sheet, floating over the map */}
      {sheet && (
        <section className="panel console rise scroll-y absolute inset-x-2 bottom-[4.5rem] top-[8.5rem] z-20 p-5 md:bottom-3 md:left-[20.5rem] md:right-3 md:top-[4.25rem] lg:p-7" aria-label={tool.t}>
          <button className="btn absolute right-4 top-4 h-8 px-2.5" onClick={() => navigate("/")} aria-label="Close and go back to the map">
            ✕
          </button>
          <Routes>
            <Route path="/alerts" element={<Alerts onOpen={(a) => { pick({ kind: "alert", alert: a }); navigate("/"); }} />} />
            <Route path="/analyze" element={<Analyze />} />
            <Route path="/tls" element={<Tls />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/detection" element={<Detection />} />
            <Route path="*" element={<p className="text-muted">There's no tool here. Pick one from the dock.</p>} />
          </Routes>
        </section>
      )}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Shell />
    </BrowserRouter>
  </StrictMode>,
);
