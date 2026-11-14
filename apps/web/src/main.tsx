import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, NavLink, Route, Routes } from "react-router";
import "@fontsource/barlow/400.css";
import "@fontsource/barlow/500.css";
import "@fontsource/barlow/600.css";
import "@fontsource/barlow-semi-condensed/500.css";
import "@fontsource/barlow-semi-condensed/600.css";
import "@fontsource/barlow-semi-condensed/700.css";
import "@fontsource/share-tech-mono/400.css";
import "@fontsource/jetbrains-mono/400.css";
import "./index.css";
import { api } from "./lib";
import { Overview } from "./pages/Overview";
import { Alerts } from "./pages/Alerts";
import { Analyze } from "./pages/Analyze";
import { Detection } from "./pages/Detection";
import { Rules } from "./pages/Rules";
import { Tls } from "./pages/Tls";

const NAV = [
  { to: "/", t: "Overview" },
  { to: "/alerts", t: "Alerts" },
  { to: "/tls", t: "TLS clients" },
  { to: "/rules", t: "Rules" },
  { to: "/analyze", t: "Analyse a pcap" },
  { to: "/detection", t: "Coverage" },
];

function Radar() {
  return (
    <svg viewBox="0 0 100 100" className="h-16 w-16" aria-hidden>
      {[46, 32, 18].map((r) => (
        <circle key={r} cx="50" cy="50" r={r} fill="none" stroke="var(--phosphor)" strokeOpacity={0.3} />
      ))}
      <line x1="4" y1="50" x2="96" y2="50" stroke="var(--phosphor)" strokeOpacity={0.18} />
      <line x1="50" y1="4" x2="50" y2="96" stroke="var(--phosphor)" strokeOpacity={0.18} />
      <g className="radar">
        <path d="M50 50 L50 4 A46 46 0 0 1 82.5 17.5 Z" fill="var(--phosphor)" fillOpacity={0.22} />
        <line x1="50" y1="50" x2="50" y2="4" stroke="var(--phosphor)" strokeWidth={1.5} />
      </g>
      <circle cx="68" cy="34" r="2.6" fill="var(--led-red)" />
      <circle cx="36" cy="64" r="1.8" fill="var(--phosphor)" />
    </svg>
  );
}

function SensorStatus() {
  const [h, setH] = useState<{ mode: string; running: boolean } | null>(null);
  useEffect(() => {
    const load = () => api<{ mode: string; running: boolean }>("/api/health").then(setH).catch(() => setH(null));
    load();
    const t = setInterval(load, 10_000);
    return () => clearInterval(t);
  }, []);
  const on = Boolean(h?.running);
  return (
    <div className="screen flex items-center gap-3 p-2.5">
      <Radar />
      <div className="lcd text-[13px] leading-snug">
        <div className="flex items-center gap-2">
          <span className={`led ${on ? "" : "led-off"}`} style={{ ["--c" as string]: "var(--led-green)" }} aria-hidden />
          {h ? (on ? "Sensing" : "Paused") : "Starting"}
        </div>
        <div className="mt-1 opacity-70">{h?.mode === "simulator" ? "Simulated office" : (h?.mode ?? "")}</div>
      </div>
    </div>
  );
}

function Shell() {
  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[250px_minmax(0,1fr)] lg:gap-4 lg:p-4 lg:pl-7">
      {/* The appliance's front panel: model plate, a push button per section, the status screen. */}
      <aside className="panel mx-3 mt-3 lg:sticky lg:top-4 lg:m-0 lg:flex lg:h-[calc(100dvh-2rem)] lg:flex-col">
        <div className="flex items-center gap-3 px-5 pb-3 pt-6">
          <a href="/" className="flex items-center gap-2.5">
            <img src="/favicon.svg" alt="" className="h-8 w-8" />
            <span>
              <span className="block font-display text-[1.35rem] font-bold leading-none [text-shadow:0_1px_0_var(--sheen)]">PacketEye</span>
              <span className="silk mt-1 block text-[11.5px]">Network sensor, model PE-2</span>
            </span>
          </a>
        </div>
        <nav className="flex gap-1.5 overflow-x-auto px-4 pb-4 lg:flex-col lg:gap-2 lg:overflow-visible" aria-label="Main">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end className="btn shrink-0 justify-start whitespace-nowrap aria-[current=page]:translate-y-px aria-[current=page]:[box-shadow:inset_0_2px_4px_var(--shade),0_1px_0_var(--sheen)]">
              {({ isActive }) => (
                <>
                  <span className={`led ${isActive ? "" : "led-off"}`} style={{ ["--c" as string]: "var(--led-green)" }} aria-hidden />
                  {n.t}
                </>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto hidden space-y-3 p-4 lg:block">
          <SensorStatus />
          <a href="https://github.com/Vishwanathanirv/real-time-intrusion-detection-system-main" className="silk block hover:text-ink">
            Source on GitHub ↗
          </a>
        </div>
      </aside>
      <div className="min-w-0">
        <main className="mx-auto max-w-[1180px] px-4 py-7 sm:px-6 lg:py-3">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/analyze" element={<Analyze />} />
            <Route path="/tls" element={<Tls />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/detection" element={<Detection />} />
            <Route path="*" element={<p className="text-muted">There's no page here. Pick a section on the panel.</p>} />
          </Routes>
        </main>
        <footer className="mx-auto max-w-[1180px] px-4 pb-8 text-xs text-muted sm:px-6">
          Built by{" "}
          <a href="https://vishwanathan.dev" className="underline underline-offset-4">
            Vishwanathan R
          </a>
          . For defensive monitoring of networks you own or are authorised to monitor.
        </footer>
      </div>
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
