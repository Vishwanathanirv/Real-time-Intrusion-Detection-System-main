import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type PointerEvent as RPointerEvent,
  type WheelEvent as RWheelEvent,
} from "react";
import { useActions } from "./actions";
import { bytes, type Alert, type Stats } from "./lib";

/** Names for the simulated office's servers. Real captures just show addresses. */
export const ROLE: Record<string, string> = {
  "10.0.0.1": "Gateway",
  "10.0.0.2": "DNS server",
  "10.0.0.10": "Web server",
  "10.0.0.20": "File server",
  "10.0.0.30": "Database",
};

type Graph = Stats["graph"];
type Node = Graph["nodes"][number] & { x: number; y: number; r: number };

const ipNum = (ip: string) =>
  ip.split(".").reduce((n, o) => n * 256 + Number(o), 0);
export const isServer = (n: { ip: string; internal: boolean }) =>
  n.internal && Number(n.ip.split(".")[3] ?? 0) < 100;

/**
 * Three columns that never move as traffic changes: workstations on the left, servers in the
 * middle, the internet on the right. Each host keeps the slot it was first given.
 */
export const LAYOUT = { width: 1240, height: 600, top: -235, bottom: 255 };
const COLUMNS = {
  workstations: [-555, -435, -315],
  servers: [0],
  internet: [410, 520],
};
const PER_COLUMN = { workstations: 8, servers: 8, internet: 9 };
const COLUMN_X = { workstations: -435, servers: 0, internet: 465 };
const INTERNET_SLOTS = PER_COLUMN.internet * COLUMNS.internet.length;

export type Seen = {
  servers: string[];
  workstations: string[];
  internet?: string[];
};

export function slot(list: string[], ip: string, xs: number[], per: number) {
  const i = Math.max(0, list.indexOf(ip));
  // Once every column is full, rows tighten instead of spilling below the map.
  const fit = Math.max(per, Math.ceil(list.length / xs.length));
  const col = Math.min(xs.length - 1, Math.floor(i / fit));
  const inCol = Math.min(fit, Math.max(1, list.length - col * fit));
  const row = Math.min(inCol - 1, i - col * fit);
  const y =
    inCol === 1
      ? 0
      : LAYOUT.top + (row / (inCol - 1)) * (LAYOUT.bottom - LAYOUT.top);
  return { x: xs[col], y };
}

export function place(
  n: Graph["nodes"][number],
  seen: Seen,
): { x: number; y: number } {
  if (isServer(n))
    return slot(seen.servers, n.ip, COLUMNS.servers, PER_COLUMN.servers);
  if (n.internal)
    return slot(
      seen.workstations,
      n.ip,
      COLUMNS.workstations,
      PER_COLUMN.workstations,
    );
  const list = (seen.internet ?? [n.ip]).slice(0, INTERNET_SLOTS);
  // Past the slots the internet column holds, hosts share the last one.
  return slot(
    list,
    list.includes(n.ip) ? n.ip : list[list.length - 1],
    COLUMNS.internet,
    PER_COLUMN.internet,
  );
}

/** A gentle curve between two hosts, so links that share a column don't overlap. */
export function link(a: { x: number; y: number }, b: { x: number; y: number }) {
  const bend = Math.abs(a.x - b.x) < 1 ? 60 : 0.12 * Math.abs(a.x - b.x);
  return `M${a.x} ${a.y} Q${(a.x + b.x) / 2} ${(a.y + b.y) / 2 - bend} ${b.x} ${b.y}`;
}

/** Alert endpoints can carry a port ("10.0.0.10:22"); the map works with hosts. */
export const hostOf = (addr: string) =>
  /^\d+\.\d+\.\d+\.\d+:\d+$/.test(addr)
    ? addr.slice(0, addr.lastIndexOf(":"))
    : addr;
export const internalIp = (ip: string) =>
  /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);

/** Orders hosts for stable slots: internal ones by address, internet ones as first seen. */
export function remember(
  seen: Required<Seen>,
  nodes: { ip: string; internal: boolean }[],
) {
  for (const n of nodes) {
    const list = isServer(n)
      ? seen.servers
      : n.internal
        ? seen.workstations
        : seen.internet;
    if (!list.includes(n.ip)) {
      list.push(n.ip);
      if (list !== seen.internet) list.sort((a, b) => ipNum(a) - ipNum(b));
    }
  }
}

export type Selection =
  { kind: "host"; ip: string } | { kind: "alert"; alert: Alert } | null;

export const VIEWBOX = `${-LAYOUT.width / 2} ${-LAYOUT.height / 2} ${LAYOUT.width} ${LAYOUT.height}`;

export function ColumnHeads({ plain }: { plain?: boolean }) {
  const heads: [number, string][] = plain
    ? [
        [COLUMN_X.workstations, "Workstations: people's computers"],
        [COLUMN_X.servers, "Servers: shared machines"],
        [COLUMN_X.internet, "Internet: anywhere outside"],
      ]
    : [
        [COLUMN_X.workstations, "Workstations"],
        [COLUMN_X.servers, "Servers"],
        [COLUMN_X.internet, "Internet"],
      ];
  return (
    <>
      {heads.map(([x, t]) => (
        <text
          key={t}
          x={x}
          y={-LAYOUT.height / 2 + 24}
          textAnchor="middle"
          fontSize={16}
          fontWeight={600}
          letterSpacing="0.02em"
          fill="var(--faint)"
        >
          {t}
        </text>
      ))}
    </>
  );
}

export function NetworkMap({
  graph,
  alerts,
  selection,
  onSelect,
}: {
  graph: Graph | undefined;
  alerts: Alert[];
  selection: Selection;
  onSelect: (s: Selection) => void;
}) {
  const svg = useRef<SVGSVGElement>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [hover, setHover] = useState<string | null>(null);
  const { plain } = useActions();
  const drag = useRef<{
    x: number;
    y: number;
    vx: number;
    vy: number;
    moved: boolean;
  } | null>(null);

  const open = useMemo(
    () => alerts.filter((a) => (a.status ?? "open") === "open"),
    [alerts],
  );
  const hotPairs = useMemo(() => {
    const set = new Set<string>();
    for (const x of open) {
      const a = hostOf(x.src);
      const b = hostOf(x.dst);
      set.add(`${a}>${b}`);
      set.add(`${b}>${a}`);
    }
    return set;
  }, [open]);
  const alarmed = useMemo(() => {
    const m = new Map<string, Alert["severity"]>();
    for (const a of open)
      for (const ip of [hostOf(a.src), hostOf(a.dst)])
        if (ip && !m.has(ip)) m.set(ip, a.severity);
    return m;
  }, [open]);

  const seen = useRef<Required<Seen>>({
    servers: [],
    workstations: [],
    internet: [],
  });
  // An attacker may send too little to rank among the busiest conversations. Hosts with open
  // alerts are always drawn, joined by their alert.
  const full = useMemo(() => {
    const nodes = [...(graph?.nodes ?? [])];
    const edges = [...(graph?.edges ?? [])];
    const have = new Set(nodes.map((n) => n.ip));
    const pairs = new Set(edges.map((e) => `${e.src}>${e.dst}`));
    const list =
      selection?.kind === "alert" ? [...open, selection.alert] : open;
    for (const a of list) {
      const src = hostOf(a.src);
      const dst = hostOf(a.dst);
      for (const ip of [src, dst]) {
        if (/^\d+\.\d+\.\d+\.\d+$/.test(ip) && !have.has(ip)) {
          have.add(ip);
          nodes.push({ ip, bytes: 0, internal: internalIp(ip) });
        }
      }
      if (
        have.has(src) &&
        have.has(dst) &&
        !pairs.has(`${src}>${dst}`) &&
        !pairs.has(`${dst}>${src}`)
      ) {
        pairs.add(`${src}>${dst}`);
        edges.push({ src, dst, bytes: 0, packets: 0, ports: [] });
      }
    }
    return { nodes, edges };
  }, [graph, open, selection]);

  const nodes: Node[] = useMemo(() => {
    remember(seen.current, full.nodes);
    return full.nodes.map((n) => ({
      ...n,
      ...place(n, seen.current),
      r: Math.max(6, Math.min(15, 3 + Math.log10(Math.max(10, n.bytes)) * 2)),
    }));
  }, [full]);
  const byIp = useMemo(() => new Map(nodes.map((n) => [n.ip, n])), [nodes]);
  const neighbours = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const e of full.edges) {
      if (!m.has(e.src)) m.set(e.src, new Set());
      if (!m.has(e.dst)) m.set(e.dst, new Set());
      m.get(e.src)!.add(e.dst);
      m.get(e.dst)!.add(e.src);
    }
    return m;
  }, [full]);
  const focus =
    selection?.kind === "host"
      ? new Set([selection.ip])
      : selection?.kind === "alert"
        ? new Set([hostOf(selection.alert.src), hostOf(selection.alert.dst)])
        : hover
          ? new Set([hover])
          : null;
  const maxEdge = Math.max(1, ...full.edges.map((e) => e.bytes));

  useEffect(() => {
    const el = svg.current;
    if (!el) return;
    // Wheel zoom needs a non-passive listener so the page doesn't scroll instead.
    const stop = (e: WheelEvent) => e.preventDefault();
    el.addEventListener("wheel", stop, { passive: false });
    return () => el.removeEventListener("wheel", stop);
  }, []);

  const zoom = (factor: number) =>
    setView((v) => ({ ...v, k: Math.max(0.6, Math.min(3, v.k * factor)) }));
  const onWheel = (e: RWheelEvent) => zoom(e.deltaY < 0 ? 1.12 : 1 / 1.12);
  const onDown = (e: RPointerEvent) => {
    drag.current = {
      x: e.clientX,
      y: e.clientY,
      vx: view.x,
      vy: view.y,
      moved: false,
    };
  };
  const onMove = (e: RPointerEvent) => {
    const d = drag.current;
    if (!d || !svg.current) return;
    const unit = LAYOUT.width / Math.max(1, svg.current.clientWidth);
    const dx = (e.clientX - d.x) * unit;
    const dy = (e.clientY - d.y) * unit;
    if (Math.abs(dx) + Math.abs(dy) > 3) d.moved = true;
    if (d.moved)
      setView((v) => ({ ...v, x: d.vx + dx / v.k, y: d.vy + dy / v.k }));
  };

  return (
    <div className="relative">
      <div className="overflow-x-auto">
        <svg
          ref={svg}
          viewBox={VIEWBOX}
          className="block aspect-[31/15] w-full min-w-[760px] touch-none select-none"
          role="group"
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
          <g transform={`scale(${view.k}) translate(${view.x} ${view.y})`}>
            <ColumnHeads plain={plain} />
            {full.edges.map((e, rank) => {
              const a = byIp.get(e.src);
              const b = byIp.get(e.dst);
              if (!a || !b) return null;
              const hot = hotPairs.has(`${e.src}>${e.dst}`);
              const dim = focus && !focus.has(e.src) && !focus.has(e.dst);
              const w = e.bytes
                ? 0.6 + (Math.log1p(e.bytes) / Math.log1p(maxEdge)) * 2.4
                : 1.6;
              const d = link(a, b);
              return (
                <g
                  key={`${e.src}>${e.dst}`}
                  opacity={dim ? 0.1 : 1}
                  fill="none"
                >
                  <path
                    d={d}
                    stroke={hot ? "var(--bad)" : "var(--accent)"}
                    strokeOpacity={hot ? 0.7 : 0.2}
                    strokeWidth={w}
                  />
                  {(hot || rank < 12 || (focus && !dim)) && (
                    <path
                      d={d}
                      stroke={hot ? "var(--bad)" : "var(--accent)"}
                      strokeOpacity={0.85}
                      strokeWidth={w + 0.4}
                      strokeLinecap="round"
                      className="flow"
                      style={{
                        ["--speed" as string]: `${Math.max(0.5, 2.6 - Math.log10(1 + e.packets))}s`,
                      }}
                    />
                  )}
                </g>
              );
            })}

            {nodes.map((n) => {
              const sev = alarmed.get(n.ip);
              const dim =
                focus &&
                !focus.has(n.ip) &&
                ![...(neighbours.get(n.ip) ?? [])].some((ip) => focus.has(ip));
              const sel = focus?.has(n.ip);
              const fill =
                sev === "critical" || sev === "high"
                  ? "var(--bad)"
                  : sev === "medium"
                    ? "var(--warn)"
                    : n.internal
                      ? "var(--node)"
                      : "var(--node-ext)";
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
                  onKeyDown={(e) => {
                    if (e.key !== "Enter" && e.key !== " ") return;
                    e.preventDefault();
                    e.stopPropagation();
                    onSelect({ kind: "host", ip: n.ip });
                  }}
                  onPointerEnter={() => setHover(n.ip)}
                  onPointerLeave={() => setHover(null)}
                >
                  {sel && (
                    <circle
                      r={n.r + 6}
                      fill="none"
                      stroke={sev ? "var(--bad)" : "var(--accent)"}
                      strokeWidth={2}
                    />
                  )}
                  <circle
                    r={n.r}
                    fill={fill}
                    stroke="var(--surface)"
                    strokeWidth={2}
                  />
                  <text
                    y={n.r + 18}
                    textAnchor="middle"
                    fontSize={14}
                    fontWeight={500}
                    fill={sel || sev ? "var(--ink)" : "var(--muted)"}
                    paintOrder="stroke"
                    stroke="var(--surface)"
                    strokeWidth={4}
                  >
                    {ROLE[n.ip] ?? n.ip}
                  </text>
                  <title>{`${ROLE[n.ip] ? `${ROLE[n.ip]} ` : ""}${n.ip}: ${bytes(n.bytes)} recently`}</title>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {!nodes.length && (
        <div className="pointer-events-none absolute inset-0 grid place-items-center">
          <p className="text-sm text-muted">Waiting for traffic…</p>
        </div>
      )}

      <div className="absolute bottom-2 right-2 flex overflow-hidden rounded-md border border-line bg-surface">
        <button
          className="h-8 w-8 hover:bg-surface-2"
          onClick={() => zoom(1.25)}
          aria-label="Zoom in"
        >
          +
        </button>
        <button
          className="h-8 w-8 border-x border-line hover:bg-surface-2"
          onClick={() => zoom(0.8)}
          aria-label="Zoom out"
        >
          −
        </button>
        <button
          className="h-8 px-2.5 text-xs font-semibold hover:bg-surface-2"
          onClick={() => setView({ x: 0, y: 0, k: 1 })}
          aria-label="Fit the map"
        >
          Fit
        </button>
      </div>
    </div>
  );
}
