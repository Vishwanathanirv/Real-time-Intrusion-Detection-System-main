import { useEffect, useMemo, useRef, useState, type PointerEvent as RPointerEvent, type WheelEvent as RWheelEvent } from "react";
import { bytes, type Alert, type Stats } from "./lib";

/** Names for the simulated office's servers. Real captures just show addresses. */
export const ROLE: Record<string, string> = { "10.0.0.1": "Gateway", "10.0.0.2": "DNS server", "10.0.0.10": "Web server", "10.0.0.20": "File server", "10.0.0.30": "Database" };

type Graph = Stats["graph"];
type Node = Graph["nodes"][number] & { x: number; y: number; r: number };

const hash = (s: string) => {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return (h >>> 0) / 4294967296;
};

/**
 * Places hosts on three rings that never move as traffic changes: servers in the middle,
 * workstations around them, the internet outside. Positions come from the address, so a host
 * stays where you last saw it.
 */
const ipNum = (ip: string) => ip.split(".").reduce((n, o) => n * 256 + Number(o), 0);
const isServer = (n: { ip: string; internal: boolean }) => n.internal && Number(n.ip.split(".")[3] ?? 0) < 100;

/** Range rings of the scope: core (servers), office (workstations), edge (the internet). */
const CORE = 120;
const OFFICE = 310;
const EDGE = 500;
const SCOPE = 560;

/** Bearing ticks every 5 degrees around the scope, longer every 30. */
const TICKS = Array.from({ length: 72 }, (_, i) => i * 5);
/** The sweep's afterglow: thin wedges that fade behind the leading edge. */
const WEDGES = Array.from({ length: 10 }, (_, i) => {
  const a0 = (-(i + 1) * 4 * Math.PI) / 180;
  const a1 = (-i * 4 * Math.PI) / 180;
  return { d: `M0 0 L${Math.cos(a0) * SCOPE} ${Math.sin(a0) * SCOPE} A${SCOPE} ${SCOPE} 0 0 1 ${Math.cos(a1) * SCOPE} ${Math.sin(a1) * SCOPE} Z`, o: 0.16 * (1 - i / 10) };
});

/** Spreads the hosts of one ring evenly, in address order. */
function ring(ips: string[], ip: string, rx: number, ry: number, turn = 0) {
  const i = ips.indexOf(ip);
  const a = (i / Math.max(1, ips.length)) * Math.PI * 2 - Math.PI / 2 + turn;
  return { x: Math.cos(a) * rx, y: Math.sin(a) * ry };
}

export function place(n: Graph["nodes"][number], seen: { servers: string[]; workstations: string[] }): { x: number; y: number } {
  if (isServer(n)) return ring(seen.servers, n.ip, CORE, CORE);
  if (n.internal) return ring(seen.workstations, n.ip, OFFICE, OFFICE, 0.12);
  const a = hash(n.ip) * Math.PI * 2;
  return { x: Math.cos(a) * EDGE, y: Math.sin(a) * EDGE };
}

/** Four corner brackets around a contact the scope has locked onto. */
const lockOn = (h: number) => {
  const l = h * 0.45;
  return [
    [-1, -1],
    [1, -1],
    [1, 1],
    [-1, 1],
  ]
    .map(([sx, sy]) => `M${sx * h} ${sy * (h - l)} L${sx * h} ${sy * h} L${sx * (h - l)} ${sy * h}`)
    .join(" ");
};

/** Alert endpoints can carry a port ("10.0.0.10:22"); the map works with hosts. */
export const hostOf = (addr: string) => (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(addr) ? addr.slice(0, addr.lastIndexOf(":")) : addr);
const internalIp = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);

export type Selection = { kind: "host"; ip: string } | { kind: "alert"; alert: Alert } | null;

export function NetworkMap({ graph, alerts, selection, onSelect }: { graph: Graph | undefined; alerts: Alert[]; selection: Selection; onSelect: (s: Selection) => void }) {
  const svg = useRef<SVGSVGElement>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 0.82 });
  const [hover, setHover] = useState<string | null>(null);
  const drag = useRef<{ x: number; y: number; vx: number; vy: number; moved: boolean } | null>(null);

  const open = alerts.filter((a) => (a.status ?? "open") === "open");
  const alarmed = useMemo(() => {
    const m = new Map<string, Alert["severity"]>();
    for (const a of open) for (const ip of [hostOf(a.src), hostOf(a.dst)]) if (ip && !m.has(ip)) m.set(ip, a.severity);
    return m;
  }, [open]);

  // Every internal host seen so far keeps its slot, so the map doesn't reshuffle as traffic changes.
  const seen = useRef({ servers: [] as string[], workstations: [] as string[] });
  // An attacker may send too little to rank among the busiest conversations. Hosts with open
  // alerts are always drawn, joined by their alert.
  const full = useMemo(() => {
    const nodes = [...(graph?.nodes ?? [])];
    const edges = [...(graph?.edges ?? [])];
    const have = new Set(nodes.map((n) => n.ip));
    const pairs = new Set(edges.map((e) => `${e.src}>${e.dst}`));
    const list = selection?.kind === "alert" ? [...open, selection.alert] : open;
    for (const a of list) {
      const src = hostOf(a.src);
      const dst = hostOf(a.dst);
      for (const ip of [src, dst]) {
        if (/^\d+\.\d+\.\d+\.\d+$/.test(ip) && !have.has(ip)) {
          have.add(ip);
          nodes.push({ ip, bytes: 0, internal: internalIp(ip) });
        }
      }
      if (have.has(src) && have.has(dst) && !pairs.has(`${src}>${dst}`) && !pairs.has(`${dst}>${src}`)) {
        pairs.add(`${src}>${dst}`);
        edges.push({ src, dst, bytes: 0, packets: 0, ports: [] });
      }
    }
    return { nodes, edges };
  }, [graph, open, selection]);

  const nodes: Node[] = useMemo(
    () => {
      const s = seen.current;
      let changed = false;
      for (const n of full.nodes) {
        const list = isServer(n) ? s.servers : n.internal ? s.workstations : null;
        if (list && !list.includes(n.ip)) {
          list.push(n.ip);
          changed = true;
        }
      }
      if (changed) {
        s.servers.sort((a, b) => ipNum(a) - ipNum(b));
        s.workstations.sort((a, b) => ipNum(a) - ipNum(b));
      }
      return full.nodes.map((n) => ({
        ...n,
        ...place(n, s),
        r: Math.max(5, Math.min(18, 3 + Math.log10(Math.max(10, n.bytes)) * 2.4)),
      }));
    },
    [full],
  );
  const byIp = new Map(nodes.map((n) => [n.ip, n]));
  const focus = selection?.kind === "host" ? new Set([selection.ip]) : selection?.kind === "alert" ? new Set([hostOf(selection.alert.src), hostOf(selection.alert.dst)]) : hover ? new Set([hover]) : null;
  const maxEdge = Math.max(1, ...full.edges.map((e) => e.bytes));

  useEffect(() => {
    const el = svg.current;
    if (!el) return;
    // Wheel zoom needs a non-passive listener so the page doesn't scroll instead.
    const stop = (e: WheelEvent) => e.preventDefault();
    el.addEventListener("wheel", stop, { passive: false });
    return () => el.removeEventListener("wheel", stop);
  }, []);

  // Start zoomed so all three rings fit whatever the screen size.
  const fit = () => {
    const el = svg.current;
    if (!el) return { x: 0, y: 0, k: 0.82 };
    const w = el.clientWidth;
    const h = el.clientHeight;
    // On wide screens the alert feed (left) and inspector (right) cover part of the map.
    const wide = w >= 768;
    const left = wide ? 330 : 0;
    const right = wide ? 390 : 0;
    const freeW = Math.max(300, w - left - right);
    const freeH = Math.max(300, h - (wide ? 170 : 260));
    const k = Math.max(0.28, Math.min(1.1, freeW / 1200, freeH / 1200));
    return { x: (left - right) / 2 / k, y: (wide ? -10 : -40) / k, k };
  };
  useEffect(() => {
    setView(fit());
  }, []);

  const zoom = (factor: number) => setView((v) => ({ ...v, k: Math.max(0.35, Math.min(3, v.k * factor)) }));
  const onWheel = (e: RWheelEvent) => zoom(e.deltaY < 0 ? 1.12 : 1 / 1.12);
  const onDown = (e: RPointerEvent) => {
    drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false };
  };
  const onMove = (e: RPointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const dx = e.clientX - d.x;
    const dy = e.clientY - d.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) d.moved = true;
    if (d.moved) setView((v) => ({ ...v, x: d.vx + dx / v.k, y: d.vy + dy / v.k }));
  };

  return (
    <div className="dots absolute inset-0">
      <svg
        ref={svg}
        className="h-full w-full touch-none select-none"
        role="img"
        aria-label={`Network map: ${nodes.length} hosts, ${full.edges.length} conversations, ${open.length} open alerts`}
        onWheel={onWheel}
        onPointerDown={onDown}
        onPointerMove={onMove}
        onPointerUp={() => {
          if (drag.current && !drag.current.moved) onSelect(null);
          drag.current = null;
        }}
        onPointerLeave={() => (drag.current = null)}
      >
        <defs>
          <radialGradient id="scope-glow">
            <stop offset="0" stopColor="var(--accent)" stopOpacity="0.09" />
            <stop offset="0.75" stopColor="var(--accent)" stopOpacity="0.03" />
            <stop offset="1" stopColor="var(--accent)" stopOpacity="0.07" />
          </radialGradient>
        </defs>
        <g style={{ transform: `translate(50%, 50%) scale(${view.k}) translate(${view.x}px, ${view.y}px)`, transition: drag.current ? "none" : "transform 0.15s ease-out" }}>
          {/* The scope: range rings, bearing ticks, crosshair and the sweep. */}
          <circle r={SCOPE} fill="url(#scope-glow)" stroke="var(--line)" />
          <line x1={-SCOPE} x2={SCOPE} y1={0} y2={0} stroke="var(--line)" strokeDasharray="1 7" />
          <line y1={-SCOPE} y2={SCOPE} x1={0} x2={0} stroke="var(--line)" strokeDasharray="1 7" />
          {[CORE, OFFICE, EDGE].map((r) => (
            <circle key={r} r={r} fill="none" stroke="var(--faint)" strokeOpacity={0.45} strokeWidth={1.2} />
          ))}
          {TICKS.map((deg) => {
            const a = ((deg - 90) * Math.PI) / 180;
            const long = deg % 30 === 0;
            const r0 = SCOPE - (long ? 16 : 7);
            return (
              <g key={deg}>
                <line x1={Math.cos(a) * r0} y1={Math.sin(a) * r0} x2={Math.cos(a) * SCOPE} y2={Math.sin(a) * SCOPE} stroke={long ? "var(--muted)" : "var(--line)"} strokeWidth={long ? 1.4 : 1} />
                {long && (
                  <text x={Math.cos(a) * (SCOPE + 20)} y={Math.sin(a) * (SCOPE + 20) + 4} textAnchor="middle" fontSize={11} className="lcd" fill="var(--faint)">
                    {String(deg).padStart(3, "0")}
                  </text>
                )}
              </g>
            );
          })}
          <g className="sweep" aria-hidden>
            {WEDGES.map((w, i) => (
              <path key={i} d={w.d} fill="var(--accent)" fillOpacity={w.o} />
            ))}
            <line x1={0} y1={0} x2={SCOPE} y2={0} stroke="var(--accent)" strokeOpacity={0.55} strokeWidth={1.5} />
          </g>
          {[
            [CORE, "CORE · servers"],
            [OFFICE, "OFFICE · workstations"],
            [EDGE, "EDGE · internet"],
          ].map(([r, t]) => (
            <text key={t} x={6} y={-(r as number) - 6} fontSize={12} letterSpacing="0.08em" fontWeight={600} fill="var(--faint)" paintOrder="stroke" stroke="var(--bg)" strokeWidth={3}>
              {t}
            </text>
          ))}

          {full.edges.map((e, rank) => {
            const a = byIp.get(e.src);
            const b = byIp.get(e.dst);
            if (!a || !b) return null;
            const hot = open.some((x) => (hostOf(x.src) === e.src && hostOf(x.dst) === e.dst) || (hostOf(x.src) === e.dst && hostOf(x.dst) === e.src));
            const dim = focus && !focus.has(e.src) && !focus.has(e.dst);
            const w = e.bytes ? 0.6 + (Math.log1p(e.bytes) / Math.log1p(maxEdge)) * 2.6 : 1.6;
            return (
              <g key={`${e.src}>${e.dst}`} opacity={dim ? 0.12 : 1}>
                <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={hot ? "var(--bad)" : "var(--accent)"} strokeOpacity={hot ? 0.6 : 0.16} strokeWidth={w} />
                {(hot || rank < 24 || (focus && !dim)) && <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={hot ? "var(--bad)" : "var(--accent)"} strokeOpacity={0.9} strokeWidth={w + 0.4} strokeLinecap="round" className="flow" style={{ ["--speed" as string]: `${Math.max(0.35, 2.4 - Math.log10(1 + e.packets))}s` }} />}
              </g>
            );
          })}

          {nodes.map((n) => {
            const sev = alarmed.get(n.ip);
            const dim = focus && !focus.has(n.ip) && !full.edges.some((e) => (focus.has(e.src) && e.dst === n.ip) || (focus.has(e.dst) && e.src === n.ip));
            const sel = focus?.has(n.ip);
            const fill = sev === "critical" || sev === "high" ? "var(--bad)" : sev === "medium" ? "var(--warn)" : n.internal ? "var(--node)" : "var(--node-ext)";
            return (
              <g
                key={n.ip}
                transform={`translate(${n.x} ${n.y})`}
                opacity={dim ? 0.25 : 1}
                className="cursor-pointer"
                role="button"
                tabIndex={0}
                aria-label={`${ROLE[n.ip] ?? n.ip}${sev ? `, ${sev} alert` : ""}`}
                onPointerDown={(e) => e.stopPropagation()}
                onPointerUp={(e) => {
                  e.stopPropagation();
                  onSelect({ kind: "host", ip: n.ip });
                }}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onSelect({ kind: "host", ip: n.ip })}
                onPointerEnter={() => setHover(n.ip)}
                onPointerLeave={() => setHover(null)}
              >
                {sev && (sev === "high" || sev === "critical") && <circle r={n.r} fill="none" stroke="var(--bad)" strokeWidth={2} className="alarm" style={{ ["--r0" as string]: `${n.r}px` }} />}
                <circle r={n.r + (sel ? 5 : 0)} fill="var(--bg)" stroke={sel ? "var(--accent)" : "none"} strokeWidth={2} />
                {sel && <path d={lockOn(n.r + 11)} fill="none" stroke={sev ? "var(--bad)" : "var(--accent)"} strokeWidth={2} strokeLinecap="square" aria-hidden />}
                <circle r={n.r} fill={fill} />
                {(ROLE[n.ip] || sel || sev || hover === n.ip) && (
                  <text y={n.r + 14} textAnchor="middle" fontSize={11} fontWeight={600} fill="var(--ink)" paintOrder="stroke" stroke="var(--bg)" strokeWidth={4}>
                    {ROLE[n.ip] ?? n.ip}
                  </text>
                )}
                <title>{`${ROLE[n.ip] ? `${ROLE[n.ip]} ` : ""}${n.ip}: ${bytes(n.bytes)} recently`}</title>
              </g>
            );
          })}
        </g>
      </svg>

      {!nodes.length && (
        <div className="pointer-events-none absolute inset-0 grid place-items-center">
          <p className="silk">Listening for traffic…</p>
        </div>
      )}

      <div className="panel absolute right-3 top-[8.25rem] flex flex-col overflow-hidden !rounded-[12px] md:bottom-[6.75rem] md:right-[24.75rem] md:top-auto">
        <button className="h-9 w-9 text-lg hover:bg-panel-2" onClick={() => zoom(1.25)} aria-label="Zoom in">
          +
        </button>
        <button className="h-9 w-9 border-y border-line text-lg hover:bg-panel-2" onClick={() => zoom(0.8)} aria-label="Zoom out">
          −
        </button>
        <button className="h-9 w-9 text-xs font-semibold hover:bg-panel-2" onClick={() => setView(fit())} aria-label="Fit the map">
          Fit
        </button>
      </div>
    </div>
  );
}
