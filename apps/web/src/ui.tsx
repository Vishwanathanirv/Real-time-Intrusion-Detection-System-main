import { useEffect, useState, type ReactNode } from "react";
import { ago, api, clock, type Alert, type Severity } from "./lib";

const SEV: Record<Severity, string> = {
  low: "bg-panel-2 text-muted",
  medium: "bg-warn-soft text-warn",
  high: "bg-bad-soft text-bad",
  critical: "bg-bad text-bg",
};

export function SevBadge({ s }: { s: Severity }) {
  return <span className={`inline-flex rounded-sm px-2 py-0.5 font-mono text-[10.5px] font-semibold uppercase tracking-wider ${SEV[s]}`}>{s}</span>;
}

export function Kpi({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  return (
    <div className="panel p-4">
      <div className="label">{label}</div>
      <div className="mt-2 font-mono text-2xl font-medium tabular-nums tracking-tight" style={{ color: tone ? `var(--${tone})` : undefined }}>
        {value}
      </div>
      {sub && <div className="mt-1 text-xs text-faint">{sub}</div>}
    </div>
  );
}

export function Panel({ title, action, children, className = "" }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
          <h2 className="font-mono text-[11.5px] uppercase tracking-[0.12em] text-muted">{title}</h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

/** Packets per second over the last two minutes, with red ticks where alerts fired. */
export function TrafficChart({ series }: { series: { t: number; packets: number; alerts: number }[] }) {
  const W = 600;
  const H = 140;
  const max = Math.max(10, ...series.map((s) => s.packets));
  const x = (i: number) => (i / Math.max(1, series.length - 1)) * W;
  const y = (v: number) => H - 4 - (v / max) * (H - 14);
  const d = series.map((s, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(s.packets).toFixed(1)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="h-36 w-full" role="img" aria-label="Packets per second">
      {[0.25, 0.5, 0.75].map((g) => (
        <line key={g} x1={0} x2={W} y1={y(max * g)} y2={y(max * g)} stroke="var(--line)" vectorEffect="non-scaling-stroke" />
      ))}
      <path d={`${d} L${W},${H} L0,${H} Z`} fill="var(--accent)" opacity={0.08} />
      <path d={d} fill="none" stroke="var(--accent)" strokeWidth={1.8} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
      {series.map((s, i) => (s.alerts ? <line key={s.t} x1={x(i)} x2={x(i)} y1={0} y2={H} stroke="var(--bad)" strokeWidth={2} opacity={0.7} vectorEffect="non-scaling-stroke" /> : null))}
      <text x={4} y={12} fontSize={10} fill="var(--faint)">
        {Math.round(max).toLocaleString()} pkt/s
      </text>
    </svg>
  );
}

export function Bars({ rows }: { rows: { label: ReactNode; value: number; hint?: string }[] }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="space-y-2.5">
      {rows.map((r, i) => (
        <div key={i} className="grid grid-cols-[minmax(0,9rem)_1fr_4.5rem] items-center gap-3 text-sm">
          <span className="truncate font-mono text-xs">{r.label}</span>
          <div className="h-1.5 overflow-hidden rounded-full bg-panel-2">
            <div className="h-full rounded-full bg-accent" style={{ width: `${(r.value / max) * 100}%` }} />
          </div>
          <span className="text-right font-mono text-xs text-faint">{r.hint}</span>
        </div>
      ))}
    </div>
  );
}

export function AlertRow({ a, fresh, onOpen, absolute }: { a: Alert; fresh?: boolean; onOpen: (a: Alert) => void; absolute?: boolean }) {
  return (
    <li>
      <button onClick={() => onOpen(a)} className={`grid w-full grid-cols-[4.5rem_1fr_auto] items-center gap-3 border-t border-line px-4 py-3 text-left hover:bg-panel-2 ${fresh ? "row-new" : ""}`}>
        <SevBadge s={a.severity} />
        <span className="min-w-0">
          <span className="block truncate text-sm">{a.title}</span>
          <span className="mt-0.5 block truncate text-xs text-faint">
            <span className="font-mono">{a.mitre.id}</span> · {a.mitre.tactic} · {a.src} → {a.dst}
          </span>
        </span>
        <span className="text-right text-xs text-faint">
          {a.count > 1 && <span className="mr-2 rounded bg-panel-2 px-1.5 py-0.5 font-mono text-muted">×{a.count}</span>}
          {absolute ? clock(a.firstSeen) : ago(a.lastSeen)}
        </span>
      </button>
    </li>
  );
}

const NEXT_STEPS: Record<string, string[]> = {
  port_scan: ["Check whether the source is an approved scanner or pentest.", "Block the source at the firewall if it is external.", "Review which ports answered: those services are now known to the attacker."],
  host_sweep: ["Identify the source machine and who is logged in.", "Look for follow-up connections from it to the hosts it found.", "Isolate it if the sweep is not expected."],
  syn_flood: ["Enable SYN cookies on the target (net.ipv4.tcp_syncookies=1).", "Rate-limit or drop at the edge, or turn on upstream DDoS protection.", "Watch the service's response time and backlog."],
  brute_force: ["Block the source and check auth logs for any successful login.", "Enforce key-based SSH and disable password login.", "Add fail2ban or an equivalent lockout."],
  dns_tunnel: ["Isolate the host: something on it is encoding data into DNS.", "Block the domain on the resolver and sinkhole it.", "Collect the process list and look for persistence."],
  beaconing: ["Treat the host as possibly compromised and isolate it.", "Look up the destination in threat intelligence.", "Find the process making the connections (ss -tp, EDR)."],
  anomaly: ["Confirm with the host owner whether the transfer is expected.", "Check the destination's reputation and the data involved.", "Tune the anomaly threshold if this is normal for your network."],
};

export function AlertDrawer({ alert, onClose, onChange }: { alert: Alert; onClose: () => void; onChange?: (a: Alert) => void }) {
  const [a, setA] = useState(alert);
  const [note, setNote] = useState(alert.note ?? "");
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);

  async function set(status: "acknowledged" | "resolved" | "open") {
    try {
      const r = await api<{ alert: Alert }>(`/api/alerts/${a.id}`, { method: "PATCH", json: { status, note: note || undefined } });
      setA(r.alert);
      onChange?.(r.alert);
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true" aria-label={a.title}>
      <button className="absolute inset-0 bg-black/50" aria-label="Close" onClick={onClose} />
      <aside className="relative h-full w-full max-w-xl overflow-y-auto border-l border-line bg-panel p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <SevBadge s={a.severity} />
            <h2 className="mt-3 text-xl font-semibold leading-snug">{a.title}</h2>
            <p className="mt-2 text-sm leading-relaxed text-muted">{a.description}</p>
          </div>
          <button className="btn h-8 px-2.5" onClick={onClose} aria-label="Close panel">
            ✕
          </button>
        </div>

        <div className="mt-6 rounded-sm border border-line p-4">
          <div className="label">MITRE ATT&amp;CK</div>
          <a className="mt-2 block text-sm hover:underline" href={`https://attack.mitre.org/techniques/${a.mitre.id.replace(".", "/")}/`} target="_blank" rel="noreferrer">
            <span className="font-mono text-accent">{a.mitre.id}</span> {a.mitre.name}
          </a>
          <div className="mt-1 text-xs text-faint">Tactic: {a.mitre.tactic}</div>
        </div>

        <dl className="mt-5 grid grid-cols-2 gap-3 text-sm">
          {[
            ["Source", a.src],
            ["Target", a.dst],
            ["First seen", clock(a.firstSeen)],
            ["Last seen", `${clock(a.lastSeen)} (${a.count}×)`],
          ].map(([k, v]) => (
            <div key={k} className="rounded-sm bg-panel-2 p-3">
              <dt className="label">{k}</dt>
              <dd className="mt-1 break-all font-mono text-xs">{v}</dd>
            </div>
          ))}
        </dl>

        <h3 className="label mt-6">Evidence</h3>
        <table className="mt-2 w-full text-sm">
          <tbody>
            {Object.entries(a.evidence).map(([k, v]) => (
              <tr key={k} className="border-t border-line">
                <td className="py-2 pr-4 text-muted">{k.replace(/([A-Z])/g, " $1").toLowerCase()}</td>
                <td className="break-all py-2 text-right font-mono text-xs">{String(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <h3 className="label mt-6">Recommended response</h3>
        <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-sm text-muted">
          {(NEXT_STEPS[a.type] ?? []).map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ol>

        <div className="mt-6 rounded-sm border border-line p-4">
          <div className="flex items-center justify-between">
            <span className="label">Triage</span>
            <span className="text-xs capitalize text-muted">Status: {a.status ?? "open"}</span>
          </div>
          <textarea className="field mt-3 h-20 py-2" placeholder="Add a note for the team (optional)" value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} />
          <div className="mt-3 flex flex-wrap gap-2">
            <button className="btn" onClick={() => set("acknowledged")}>
              Acknowledge
            </button>
            <button className="btn btn-accent" onClick={() => set("resolved")}>
              Resolve
            </button>
            {a.status && a.status !== "open" && (
              <button className="btn" onClick={() => set("open")}>
                Reopen
              </button>
            )}
          </div>
          {err && <p className="mt-2 text-sm text-bad">{err}</p>}
        </div>
      </aside>
    </div>
  );
}
