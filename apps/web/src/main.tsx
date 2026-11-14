import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, NavLink, Route, Routes } from "react-router";
import "@fontsource-variable/space-grotesk";
import "@fontsource/jetbrains-mono/400.css";
import "./index.css";
import { api } from "./lib";
import { Overview } from "./pages/Overview";
import { Alerts } from "./pages/Alerts";
import { Analyze } from "./pages/Analyze";
import { Detection } from "./pages/Detection";

const NAV = [
  { to: "/", n: "01", t: "Overview" },
  { to: "/alerts", n: "02", t: "Alerts" },
  { to: "/analyze", n: "03", t: "Analyse pcap" },
  { to: "/detection", n: "04", t: "Coverage" },
];

function Radar() {
  return (
    <svg viewBox="0 0 100 100" className="h-20 w-20" aria-hidden>
      {[46, 32, 18].map((r) => (
        <circle key={r} cx="50" cy="50" r={r} fill="none" stroke="var(--accent)" strokeOpacity={0.35} />
      ))}
      <line x1="4" y1="50" x2="96" y2="50" stroke="var(--accent)" strokeOpacity={0.2} />
      <line x1="50" y1="4" x2="50" y2="96" stroke="var(--accent)" strokeOpacity={0.2} />
      <g className="radar">
        <path d="M50 50 L50 4 A46 46 0 0 1 82.5 17.5 Z" fill="var(--accent)" fillOpacity={0.22} />
        <line x1="50" y1="50" x2="50" y2="4" stroke="var(--accent)" strokeWidth={1.5} />
      </g>
      <circle cx="68" cy="34" r="2.6" fill="var(--bad)" />
      <circle cx="36" cy="64" r="1.8" fill="var(--accent)" />
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
  return (
    <div className="panel p-4">
      <div className="flex items-center gap-3">
        <Radar />
        <div>
          <div className="label">Sensor</div>
          <div className={`mt-1 font-mono text-sm ${h?.running ? "text-ok" : "text-faint"}`}>{h ? (h.running ? "● ONLINE" : "○ PAUSED") : "○ …"}</div>
          <div className="mt-0.5 font-mono text-[11px] uppercase text-muted">{h?.mode ?? ""}</div>
        </div>
      </div>
    </div>
  );
}

function Shell() {
  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[240px_minmax(0,1fr)]">
      <aside className="border-b border-line bg-panel/80 backdrop-blur lg:sticky lg:top-0 lg:flex lg:h-dvh lg:flex-col lg:border-b-0 lg:border-r">
        <div className="flex items-center gap-3 px-4 py-4 lg:px-5 lg:py-6">
          <a href="/" className="flex items-center gap-2.5">
            <img src="/favicon.svg" alt="" className="h-8 w-8" />
            <span>
              <span className="block text-lg font-bold leading-none tracking-tight">PacketEye</span>
              <span className="mt-1 block font-mono text-[10px] uppercase tracking-[0.18em] text-faint">Network IDS · v2</span>
            </span>
          </a>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-3 lg:flex-col lg:px-3 lg:pb-0" aria-label="Main">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end
              className={({ isActive }) =>
                `flex items-center gap-3 whitespace-nowrap rounded-sm border-l-2 px-3 py-2 text-sm ${isActive ? "border-accent bg-panel-2 text-ink" : "border-transparent text-muted hover:text-ink"}`
              }
            >
              <span className="font-mono text-[11px] text-faint">{n.n}</span>
              {n.t}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto hidden space-y-3 p-4 lg:block">
          <SensorStatus />
          <a href="https://github.com/Vishwanathanirv/real-time-intrusion-detection-system-main" className="block font-mono text-[11px] uppercase tracking-wider text-muted hover:text-accent">
            Source on GitHub ↗
          </a>
        </div>
      </aside>
      <div className="min-w-0">
        <main className="mx-auto max-w-[1180px] px-4 py-7 sm:px-8">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/analyze" element={<Analyze />} />
            <Route path="/detection" element={<Detection />} />
            <Route path="*" element={<p className="text-muted">Page not found.</p>} />
          </Routes>
        </main>
        <footer className="mx-auto max-w-[1180px] px-4 pb-8 font-mono text-[11px] text-faint sm:px-8">
          Built by{" "}
          <a href="https://vishwanathan.dev" className="text-muted underline underline-offset-4">
            Vishwanathan R
          </a>{" "}
          · For defensive monitoring of networks you own or are authorised to monitor.
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
