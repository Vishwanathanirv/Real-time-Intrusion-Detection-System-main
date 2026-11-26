import { lazy, StrictMode, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Link, NavLink, Route, Routes, useLocation, useNavigate } from "react-router";
import "@fontsource-variable/public-sans";
import "@fontsource-variable/fira-code";
import "./index.css";
import { api, bytes, clock, num, useLive, usePoll, type Alert } from "./lib";
import { hostOf, NetworkMap, ROLE, type Selection } from "./map";
import { buildReport, encodeReport } from "./report-codec";
import { Palette, type Command } from "./palette";
import { useAlertSound } from "./sound";
import { ActionsContext, Plain, usePlainSetting, type Actions } from "./actions";
import { alertsAt, canReplay, frameAt, incidentWindow, Scrubber, useReplayClock, type Replay } from "./replay";
import { AlertBody, Bars, SevBadge, Strip, TrafficChart } from "./ui";

// Each tool loads when it is first opened, so the overview paints first.
const Alerts = lazy(() => import("./pages/Alerts").then((m) => ({ default: m.Alerts })));
const Analyze = lazy(() => import("./pages/Analyze").then((m) => ({ default: m.Analyze })));
const Detection = lazy(() => import("./pages/Detection").then((m) => ({ default: m.Detection })));
const Lab = lazy(() => import("./pages/Lab").then((m) => ({ default: m.Lab })));
const Report = lazy(() => import("./pages/Report").then((m) => ({ default: m.Report })));
const Rules = lazy(() => import("./pages/Rules").then((m) => ({ default: m.Rules })));
const Tls = lazy(() => import("./pages/Tls").then((m) => ({ default: m.Tls })));

function Loading() {
  return (
    <div className="space-y-3 p-1" aria-label="Loading">
      <div className="skeleton h-9 w-1/3" />
      <div className="skeleton h-5 w-2/3" />
      <div className="skeleton h-48" />
    </div>
  );
}

const TOOLS: { to: string; t: string; short: string; icon: string }[] = [
  { to: "/", t: "Overview", short: "Overview", icon: "M3 6l6-2 6 2 6-2v14l-6 2-6-2-6 2zM9 4v14M15 6v14" },
  { to: "/alerts", t: "Alerts", short: "Alerts", icon: "M12 3l9 16H3zM12 10v4M12 17h.01" },
  { to: "/lab", t: "What-if lab", short: "Lab", icon: "M9 3h6M10 3v6L4 19a1 1 0 0 0 .9 1.5h14.2A1 1 0 0 0 20 19l-6-10V3M7 14h10" },
  { to: "/tls", t: "TLS clients", short: "TLS", icon: "M6 11V8a6 6 0 0 1 12 0v3M5 11h14v10H5zM12 15v2" },
  { to: "/rules", t: "Rules", short: "Rules", icon: "M5 4h14v16H5zM8 8h8M8 12h8M8 16h5" },
  { to: "/analyze", t: "Analyse a pcap", short: "Pcap", icon: "M12 3v12M7 10l5 5 5-5M4 19h16" },
  { to: "/detection", t: "Coverage", short: "Coverage", icon: "M4 20V10M10 20V4M16 20v-8M22 20H2" },
];

function Icon({ d, className = "h-[18px] w-[18px]" }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d={d} />
    </svg>
  );
}

type Live = ReturnType<typeof useLive>;

/** What the inspector shows when nothing is selected: the network right now. */
function NetworkNow({ live }: { live: Live }) {
  const s = live.stats;
  const total = s ? Object.values(s.protocols).reduce((a, b) => a + b, 0) || 1 : 1;
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold">The network right now</h2>
        <p className="mt-1 text-sm text-muted">{s?.state.mode === "capture" ? "Live capture from a network interface." : "Simulated office: 24 workstations, five servers. Select a host to inspect it."}</p>
        <Plain className="mt-3">Each dot is a computer and each line is two of them talking; thicker means more data. When something looks like an attack, its hosts and line turn red and it appears in the alert list.</Plain>
      </div>
      <section>
        <h3 className="label">Busiest hosts</h3>
        <div className="mt-2">
          <Bars rows={(s?.topTalkers ?? []).slice(0, 6).map((t) => ({ label: ROLE[t.ip] ?? t.ip, value: t.bytes, hint: bytes(t.bytes) }))} />
        </div>
      </section>
      <section>
        <h3 className="label">Protocols</h3>
        <div className="mt-2 flex h-2 overflow-hidden rounded-sm bg-surface-2">
          {s && (["tcp", "udp", "icmp"] as const).map((p, i) => <div key={p} style={{ width: `${(s.protocols[p] / total) * 100}%`, background: ["var(--accent)", "var(--muted)", "var(--warn)"][i] }} />)}
        </div>
        <div className="mt-1.5 flex gap-4 text-xs text-muted">
          {s &&
            (["tcp", "udp", "icmp"] as const).map((p) => (
              <span key={p} className="lcd">
                {p.toUpperCase()} {Math.round((s.protocols[p] / total) * 100)}%
              </span>
            ))}
        </div>
      </section>
      <section>
        <h3 className="label">Busiest ports</h3>
        <Plain className="mt-1.5">A port is a numbered door on a computer: 443 is websites, 53 is the phone book (DNS), 22 is remote login.</Plain>
        <div className="mt-2">
          <Bars rows={(s?.topPorts ?? []).slice(0, 5).map((p) => ({ label: `:${p.port}`, value: p.packets, hint: num(p.packets) }))} />
        </div>
      </section>
      <p className="border-t border-line pt-3 text-xs text-faint">Monitor only networks you own or are allowed to monitor.</p>
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
    <div className="space-y-6">
      <div>
        <div className="silk">{node?.internal === false ? "On the internet" : ROLE[ip] ? "Server" : "Workstation"}</div>
        <h2 className="lcd mt-1 text-lg font-medium">{ROLE[ip] ?? ip}</h2>
        {ROLE[ip] && <div className="lcd text-sm text-muted">{ip}</div>}
        <button
          className="btn mt-3 h-8"
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
      <section>
        <h3 className="label">Alerts involving it ({related.length})</h3>
        {related.length ? (
          <ul className="mt-2 space-y-1.5">
            {related.slice(0, 8).map((a) => (
              <li key={a.id}>
                <button className="screen flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-line" onClick={() => onAlert(a)}>
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
            <Bars
              rows={peers
                .slice(0, 8)
                .map((e) => ({ label: `${e.src === ip ? "→" : "←"} ${ROLE[e.src === ip ? e.dst : e.src] ?? (e.src === ip ? e.dst : e.src)}`, value: e.bytes, hint: e.ports.length ? `:${e.ports.slice(0, 2).join(" :")}` : bytes(e.bytes) }))}
            />
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
  const { data: attackList } = usePoll<{ attacks: { kind: string; label: string }[] }>("/api/attacks", 0);
  const [attack, setAttack] = useState("port_scan");
  const [msg, setMsg] = useState<string | null>(null);
  const [replay, setReplay] = useState<Replay | null>(null);
  const [palette, setPalette] = useState(false);
  const sound = useAlertSound();
  const inspectorRef = useRef<HTMLElement>(null);
  // A chime for every alert that is new since the page opened, when the sound is on.
  const heard = useRef<Set<string> | null>(null);
  useEffect(() => {
    if (!live.connected) return;
    if (!heard.current) {
      heard.current = new Set(live.alerts.map((a) => a.id));
      return;
    }
    for (const a of live.alerts)
      if (!heard.current.has(a.id)) {
        heard.current.add(a.id);
        sound.chime(a.severity);
      }
  }, [live.alerts, live.connected, sound]);
  const s = live.stats;
  const frames = live.frames;
  const newest = frames[frames.length - 1]?.t ?? Date.now();
  useReplayClock(replay, newest, setReplay);
  const rewind = useCallback(() => {
    if (frames.length < 2) return;
    navigate("/");
    setReplay({ t: Math.max(frames[0].t, newest - 60_000), playing: true, speed: 4 });
  }, [frames, newest, navigate]);
  const pick = useCallback((x: Selection) => {
    setSel(x);
    // On narrow screens the inspector sits below the map; bring it into view.
    if (x && !matchMedia("(min-width: 1024px)").matches) requestAnimationFrame(() => inspectorRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }, []);
  const replayAlert = useCallback(
    (a: Alert) => {
      const w = incidentWindow(a, frames);
      navigate("/");
      setSel({ kind: "alert", alert: a });
      setReplay({ t: w.from, playing: true, speed: 2, alertId: a.id });
    },
    [frames, navigate],
  );
  const [plain, setPlain] = usePlainSetting();
  const share = useCallback(async (a: Alert) => `${location.origin}/report#${await encodeReport(buildReport(a, frames))}`, [frames]);
  const actions = useMemo<Actions>(() => ({ replay: replayAlert, canReplay: (a) => canReplay(a, frames), share, plain, setPlain }), [replayAlert, frames, share, plain, setPlain]);
  const frame = replay ? frameAt(frames, replay.t) : undefined;
  const shownAlerts = replay ? alertsAt(live.alerts, replay.t) : live.alerts;
  const last = s?.series.slice(-5) ?? [];
  const pps = last.length ? Math.round(last.reduce((a, x) => a + x.packets, 0) / last.length) : 0;
  const bps = last.length ? last.reduce((a, x) => a + x.bytes, 0) / last.length : 0;
  const open = live.alerts.filter((a) => (a.status ?? "open") === "open");
  const home = loc.pathname === "/";
  const tool = TOOLS.find((t) => t.to === loc.pathname);
  const status = !live.connected ? "Connecting" : replay ? "Replaying" : s?.state.running === false ? "Paused" : "Live";

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setPalette((v) => !v);
        return;
      }
      if (["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName) || e.metaKey || e.ctrlKey || e.altKey || palette) return;
      if (e.key === "/" || e.key === "?") {
        e.preventDefault();
        setPalette(true);
        return;
      }
      if (e.key === "m" || e.key === "M") sound.toggle();
      if (e.key === "Escape") {
        if (!home) navigate("/");
        else if (replay) setReplay(null);
        else setSel(null);
      }
      if (e.key === "r" || e.key === "R") {
        if (replay) setReplay(null);
        else rewind();
      }
      if ((e.key === "l" || e.key === "L") && replay) setReplay(null);
      if (e.key === "e" || e.key === "E") setPlain(!plain);
      if (e.key === " " && replay && !(el.closest("button") || el.getAttribute("role") === "slider")) {
        e.preventDefault();
        setReplay({ ...replay, playing: !replay.playing });
      }
      const n = Number(e.key);
      if (n >= 1 && n <= TOOLS.length) navigate(TOOLS[n - 1].to);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [home, navigate, replay, rewind, plain, setPlain, palette, sound]);

  // Following a launched attack: select the first alert it raises.
  const following = useRef(0);
  async function launch(kind = attack, follow = false) {
    setMsg(null);
    try {
      await api("/api/attacks", { method: "POST", json: { kind } });
      if (follow) following.current = Date.now();
      setMsg(`${attackList?.attacks.find((a) => a.kind === kind)?.label ?? "Attack"} launched.`);
      setTimeout(() => setMsg(null), 4000);
    } catch (e) {
      setMsg((e as Error).message);
    }
  }
  useEffect(() => {
    if (!following.current) return;
    const hit = live.alerts.find((a) => a.firstSeen >= following.current - 1000);
    if (hit) {
      following.current = 0;
      pick({ kind: "alert", alert: hit });
    }
  }, [live.alerts, pick]);
  async function setLive(next: { running?: boolean; autopilot?: boolean }) {
    try {
      await api("/api/live", { method: "PUT", json: next });
    } catch (e) {
      setMsg((e as Error).message);
    }
  }

  const latest = live.alerts[0];
  const commands: Command[] = [
    ...(attackList?.attacks ?? []).map((a) => ({ id: `launch-${a.kind}`, group: "Simulate an attack", label: `Launch: ${a.label}`, run: () => (navigate("/"), void launch(a.kind, true)) })),
    { id: "rewind", group: "Monitor", label: replay ? "Back to live" : "Rewind the last minute", keys: "R", run: () => (replay ? setReplay(null) : rewind()) },
    ...(latest ? [{ id: "replay-latest", group: "Monitor", label: `Replay the latest incident: ${latest.title}`, run: () => replayAlert(latest) }] : []),
    ...(latest ? [{ id: "share-latest", group: "Monitor", label: "Share the latest alert as a report", run: () => void share(latest).then((url) => location.assign(url)) }] : []),
    { id: "pause", group: "Monitor", label: s?.state.running === false ? "Resume the sensor" : "Pause the sensor", run: () => void setLive({ running: !(s?.state.running ?? true) }) },
    { id: "autopilot", group: "Monitor", label: s?.state.autopilot ? "Turn autopilot off" : "Turn autopilot on (random attacks)", run: () => void setLive({ autopilot: !s?.state.autopilot }) },
    ...TOOLS.map((t, i) => ({ id: `tool-${t.to}`, group: "Open", label: t.t, keys: String(i + 1), run: () => navigate(t.to) })),
    { id: "explain", group: "Settings", label: plain ? "Explain like I'm new: turn off" : "Explain like I'm new: turn on", keys: "E", run: () => setPlain(!plain) },
    { id: "sound", group: "Settings", label: sound.on ? "Alert sound: turn off" : "Alert sound: chime on every new alert", keys: "M", run: sound.toggle },
  ];

  const inspectorBody = useMemo<ReactNode>(() => {
    if (sel?.kind === "alert") return <AlertBody key={sel.alert.id} alert={live.alerts.find((a) => a.id === sel.alert.id) ?? sel.alert} />;
    if (sel?.kind === "host") return <HostCard ip={sel.ip} live={live} onAlert={(a) => pick({ kind: "alert", alert: a })} />;
    return <NetworkNow live={live} />;
  }, [sel, live, pick]);

  const metrics: [string, string, boolean?][] = [
    ["Packets/s", num(pps)],
    ["Bandwidth/s", bytes(bps)],
    ["Flows", s ? num(s.activeFlows) : "–"],
    ["Open alerts", String(open.length), open.length > 0],
  ];

  return (
    <ActionsContext.Provider value={actions}>
      <div className="grid h-dvh grid-rows-[auto_minmax(0,1fr)_auto] md:grid-cols-[13.5rem_minmax(0,1fr)] md:grid-rows-[auto_minmax(0,1fr)]">
        <header className="topbar md:col-span-2">
          <Link to="/" className="flex items-center gap-2.5" aria-label="PacketEye overview">
            <img src="/favicon.svg" alt="" className="h-6 w-6" />
            <span className="text-[1.02rem] font-bold tracking-tight">PacketEye</span>
          </Link>
          <span className="inline-flex items-center gap-2 text-sm text-muted" aria-live="polite">
            <span className="led" style={{ ["--c" as string]: status === "Live" ? "var(--ok)" : status === "Replaying" ? "var(--warn)" : "var(--faint)" }} aria-hidden />
            {status}
          </span>
          <dl className="hidden flex-1 items-center justify-center gap-8 lg:flex" aria-label="Network now">
            {metrics.map(([k, v, hot]) => (
              <div key={k} className="metric">
                <dt>{k}</dt>
                <dd style={hot ? { color: "var(--bad)" } : undefined}>{v}</dd>
              </div>
            ))}
          </dl>
          <div className="ml-auto flex items-center gap-1.5">
            <button className="btn h-8 px-2.5" onClick={() => setPalette(true)} aria-label="Command menu" title="Command menu (Ctrl+K or /)">
              <Icon className="h-4 w-4" d="M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-5-5" />
              <kbd className="lcd hidden text-[11px] text-faint sm:inline">Ctrl K</kbd>
            </button>
            <button className="btn h-8 px-2.5" onClick={sound.toggle} aria-pressed={sound.on} aria-label="Alert sound" title="Alert sound: chime on every new alert (M)">
              <Icon className="h-4 w-4" d={sound.on ? "M11 5L6 9H3v6h3l5 4zM15.5 8.5a5 5 0 0 1 0 7M18.5 5.5a9 9 0 0 1 0 13" : "M11 5L6 9H3v6h3l5 4zM22 9l-6 6M16 9l6 6"} />
            </button>
            <button className="btn h-8 px-2.5" onClick={() => setPlain(!plain)} aria-pressed={plain} aria-label="Explain like I'm new" title="Explain like I'm new (E)">
              <Icon className="h-4 w-4" d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z" />
              <span className="hidden sm:inline">Explain</span>
            </button>
          </div>
        </header>

        <nav className="row-start-3 flex justify-around border-t border-line bg-surface px-1 md:row-start-2 md:flex-col md:justify-start md:gap-0.5 md:border-r md:border-t-0 md:p-3" aria-label="Tools">
          {TOOLS.map((t, i) => (
            <NavLink key={t.to} to={t.to} end className="navlink" title={`${t.t} (${i + 1})`}>
              <Icon d={t.icon} />
              <span className="md:hidden">{t.short}</span>
              <span className="hidden md:inline">{t.t}</span>
              <kbd>{i + 1}</kbd>
            </NavLink>
          ))}
        </nav>

        <main className="scroll-y min-w-0" aria-label={tool?.t ?? "PacketEye"}>
          {home ? (
            <div className="mx-auto grid max-w-[1500px] gap-5 p-4 md:p-6 lg:grid-cols-[minmax(0,1fr)_23rem]">
              <div className="min-w-0 space-y-5">
                <dl className="grid grid-cols-2 gap-x-6 gap-y-3 lg:hidden" aria-label="Network now, summary">
                  {metrics.map(([k, v, hot]) => (
                    <div key={k} className="metric">
                      <dt>{k}</dt>
                      <dd style={hot ? { color: "var(--bad)" } : undefined}>{v}</dd>
                    </div>
                  ))}
                </dl>
                <Plain>Packets are the small envelopes all network data travels in. A flow is one conversation between two computers. Every alert is something that looked like an attack.</Plain>

                <section className="panel" aria-label="Traffic">
                  <div className="section-head">
                    <h2>{replay ? "Rewind" : "Traffic, last two minutes"}</h2>
                    {!replay && (
                      <button className="btn btn-warn h-8" onClick={rewind} disabled={frames.length < 2} title="Rewind the last minute (R)">
                        <Icon className="h-4 w-4" d="M3 12a9 9 0 1 0 3-6.7M3 4v5h5M12 8v4l3 2" />
                        Rewind
                      </button>
                    )}
                  </div>
                  <div className="p-4">
                    {replay ? (
                      <Scrubber frames={frames} alerts={live.alerts} replay={replay} onChange={setReplay} onExit={() => setReplay(null)} />
                    ) : s ? (
                      <TrafficChart series={s.series} height={96} onPick={(t) => frames.length > 1 && setReplay({ t: Math.max(frames[0].t, t), playing: true, speed: 2 })} />
                    ) : (
                      <div className="skeleton h-24" />
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-2 border-t border-line px-4 py-3">
                    <span className="silk mr-1">Simulator</span>
                    <select className="field h-9 w-auto min-w-[10rem] flex-1 sm:flex-none" value={attack} onChange={(e) => setAttack(e.target.value)} aria-label="Attack to simulate" disabled={s?.state.mode !== "simulator"}>
                      {(attackList?.attacks ?? []).map((a) => (
                        <option key={a.kind} value={a.kind}>
                          {a.label}
                        </option>
                      ))}
                    </select>
                    <button className="btn btn-accent h-9" onClick={() => void launch()} disabled={s?.state.mode !== "simulator"}>
                      Launch
                    </button>
                    <Link to="/lab" className="btn h-9" title="What-if lab (3)">
                      What if…?
                    </Link>
                    <button className="btn h-9" onClick={() => setLive({ running: !(s?.state.running ?? true) })} disabled={!s}>
                      {s?.state.running === false ? "Resume" : "Pause"}
                    </button>
                    <label className="silk flex items-center gap-1.5">
                      <input type="checkbox" checked={Boolean(s?.state.autopilot)} onChange={(e) => setLive({ autopilot: e.target.checked })} disabled={s?.state.mode !== "simulator"} className="accent-[var(--accent)]" />
                      Autopilot
                    </label>
                    {msg && (
                      <p className="w-full text-xs text-muted" aria-live="polite">
                        {msg}
                      </p>
                    )}
                  </div>
                </section>

                <section className="panel" aria-label="Network">
                  <div className="section-head">
                    <h2>Network</h2>
                    {replay ? <span className="tape-badge">REPLAY · {clock(replay.t)}</span> : <span className="text-xs text-faint">Drag to pan, scroll to zoom</span>}
                  </div>
                  <div className="p-2">
                    <NetworkMap graph={replay ? frame?.graph : s?.graph} alerts={shownAlerts} selection={sel} onSelect={pick} />
                  </div>
                </section>

                <section className="panel" aria-label="Recent alerts">
                  <div className="section-head">
                    <h2>Recent alerts</h2>
                    <Link to="/alerts" className="text-sm font-semibold text-accent hover:underline">
                      All alerts
                    </Link>
                  </div>
                  {shownAlerts.length ? (
                    <ul>
                      {shownAlerts.slice(0, 6).map((a) => (
                        <li key={a.id}>
                          <Strip a={a} fresh={live.isFresh(a.id)} onOpen={(x) => pick({ kind: "alert", alert: x })} route={`${ROLE[hostOf(a.src)] ?? a.src} → ${ROLE[hostOf(a.dst)] ?? a.dst}`} />
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="px-4 py-6 text-sm text-muted">{replay ? "No alerts had been raised at this moment." : live.connected ? "No alerts. Launch an attack from the simulator to see detection work." : "Connecting to the sensor…"}</p>
                  )}
                </section>
              </div>

              <aside ref={inspectorRef} className="panel h-fit scroll-y scroll-mt-4 p-5 lg:sticky lg:top-0 lg:max-h-[calc(100dvh-7rem)]" aria-label="Inspector">
                <div className="mb-4 flex items-center justify-between">
                  <span className="silk">{sel?.kind === "alert" ? "Alert" : sel?.kind === "host" ? "Host" : "Summary"}</span>
                  {sel && (
                    <button className="btn h-7 px-2 text-xs" onClick={() => setSel(null)}>
                      Clear
                    </button>
                  )}
                </div>
                {inspectorBody}
              </aside>
            </div>
          ) : (
            <section className="mx-auto max-w-6xl p-4 md:p-8" aria-label={tool?.t ?? "Not found"}>
              <Suspense fallback={<Loading />}>
                <Routes>
                  <Route
                    path="/alerts"
                    element={
                      <Alerts
                        onOpen={(a) => {
                          navigate("/");
                          pick({ kind: "alert", alert: a });
                        }}
                      />
                    }
                  />
                  <Route path="/analyze" element={<Analyze />} />
                  <Route path="/lab" element={<Lab live={s?.state.mode === "simulator"} />} />
                  <Route path="/tls" element={<Tls />} />
                  <Route path="/rules" element={<Rules />} />
                  <Route path="/detection" element={<Detection />} />
                  <Route
                    path="*"
                    element={
                      <div className="py-16">
                        <h1 className="text-2xl font-bold">Nothing here</h1>
                        <p className="mt-2 text-muted">
                          Pick a tool from the menu, or go to the{" "}
                          <Link to="/" className="text-accent underline underline-offset-2">
                            overview
                          </Link>
                          .
                        </p>
                      </div>
                    }
                  />
                </Routes>
              </Suspense>
            </section>
          )}
        </main>

        {palette && <Palette commands={commands} onClose={() => setPalette(false)} />}
      </div>
    </ActionsContext.Provider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Suspense fallback={<div className="h-dvh bg-bg" />}>
        <Routes>
          <Route path="/report" element={<Report />} />
          <Route path="*" element={<Shell />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  </StrictMode>,
);
