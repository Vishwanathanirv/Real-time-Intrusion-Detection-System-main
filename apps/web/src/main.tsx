import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, NavLink, Route, Routes } from "react-router";
import "@fontsource-variable/inter";
import "@fontsource/jetbrains-mono/400.css";
import "./index.css";
import { Overview } from "./pages/Overview";
import { Alerts } from "./pages/Alerts";
import { Analyze } from "./pages/Analyze";
import { Detection } from "./pages/Detection";

const NAV = [
  { to: "/", t: "Overview" },
  { to: "/alerts", t: "Alerts" },
  { to: "/analyze", t: "Analyse pcap" },
  { to: "/detection", t: "Coverage" },
];

function Shell() {
  return (
    <div className="min-h-dvh">
      <header className="sticky top-0 z-30 border-b border-line bg-bg/85 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-7xl items-center gap-6 px-4 sm:px-6">
          <a href="/" className="flex items-center gap-2 font-semibold tracking-tight">
            <img src="/favicon.svg" alt="" className="h-6 w-6" />
            PacketEye
          </a>
          <nav className="flex flex-1 gap-1 overflow-x-auto text-sm" aria-label="Main">
            {NAV.map((n) => (
              <NavLink key={n.to} to={n.to} end className={({ isActive }) => `whitespace-nowrap rounded-lg px-3 py-1.5 ${isActive ? "bg-panel-2 text-ink" : "text-muted hover:text-ink"}`}>
                {n.t}
              </NavLink>
            ))}
          </nav>
          <a href="https://github.com/Vishwanathanirv/real-time-intrusion-detection-system-main" className="hidden text-sm text-muted hover:text-ink sm:block">
            GitHub
          </a>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-7 sm:px-6">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/analyze" element={<Analyze />} />
          <Route path="/detection" element={<Detection />} />
          <Route path="*" element={<p className="text-muted">Page not found.</p>} />
        </Routes>
      </main>
      <footer className="mx-auto max-w-7xl px-4 pb-8 text-xs text-faint sm:px-6">
        Built by{" "}
        <a href="https://vishwanathan.dev" className="text-muted underline underline-offset-4">
          Vishwanathan R
        </a>{" "}
        · For defensive monitoring of networks you own or are authorised to monitor.
      </footer>
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
