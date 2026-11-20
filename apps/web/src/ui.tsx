import { useEffect, useState, type ReactNode } from "react";
import { useActions } from "./actions";
import { ago, api, clock, type Alert, type Severity } from "./lib";

/** Lamp colour per severity: the LEDs on the front of the box. */
const LAMP: Record<Severity, string> = { low: "var(--faint)", medium: "var(--warn)", high: "var(--bad)", critical: "var(--bad)" };

export function SevBadge({ s }: { s: Severity }) {
  return (
    <span className="inline-flex items-center gap-2 text-[13px] font-semibold capitalize" style={{ color: s === "low" ? "var(--muted)" : s === "medium" ? "var(--warn)" : "var(--bad)" }}>
      <span className={`led ${s === "critical" ? "blink" : ""}`} style={{ ["--c" as string]: LAMP[s] }} aria-hidden />
      {s}
    </span>
  );
}

/** An instrument readout: a figure under a tick scale, like a dial on the scope console. */
export function Kpi({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  return (
    <div className="readout">
      <div className="readout-label">{label}</div>
      <div className="lcd mt-1 whitespace-nowrap text-[1.15rem] font-medium leading-none" style={tone === "bad" ? { color: "var(--bad)" } : tone === "accent" ? { color: "var(--accent)" } : undefined}>
        {value}
      </div>
      {sub && <div className="mt-1 text-[11.5px] text-faint">{sub}</div>}
    </div>
  );
}

export function Panel({ title, action, children, className = "" }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`overflow-hidden rounded-[16px] border border-line bg-panel-solid ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between gap-3 px-4 pb-2 pt-3">
          <h2 className="text-[0.95rem] font-semibold">{title}</h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

/** Packets per second over the last two minutes, with a coral tick where an alert fired. */
export function TrafficChart({ series, height = 160, onPick }: { series: { t: number; packets: number; alerts: number }[]; height?: number; onPick?: (t: number) => void }) {
  const W = 600;
  const H = 140;
  const max = Math.max(10, ...series.map((s) => s.packets));
  const x = (i: number) => (i / Math.max(1, series.length - 1)) * W;
  const y = (v: number) => H - 4 - (v / max) * (H - 14);
  const d = series.map((s, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(s.packets).toFixed(1)}`).join(" ");
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="block w-full" style={{ height }} role="img" aria-label="Packets per second, last two minutes">
        <defs>
          <linearGradient id="tc-fill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stopColor="var(--accent)" stopOpacity="0.3" />
            <stop offset="1" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {series.length > 1 && <path d={`${d} L${W},${H} L0,${H} Z`} fill="url(#tc-fill)" />}
        <path d={d} fill="none" stroke="var(--accent)" strokeWidth={1.8} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
        {series.map((s, i) => (s.alerts ? <line key={s.t} x1={x(i)} x2={x(i)} y1={0} y2={H} stroke="var(--bad)" strokeWidth={2} vectorEffect="non-scaling-stroke" /> : null))}
        {onPick &&
          series.map((s, i) => (
            <rect key={`h${s.t}`} x={x(i) - W / series.length / 2} width={W / series.length} y={0} height={H} fill="transparent" onClick={() => onPick(s.t)}>
              <title>{`${new Date(s.t).toLocaleTimeString("en-IN", { hour12: false })}: ${s.packets} packets${s.alerts ? `, ${s.alerts} alert${s.alerts > 1 ? "s" : ""}` : ""}`}</title>
            </rect>
          ))}
      </svg>
      <span className="lcd pointer-events-none absolute left-2 top-1 text-[10px] text-faint">{Math.round(max).toLocaleString()} pkt/s</span>
    </div>
  );
}

export function Bars({ rows }: { rows: { label: ReactNode; value: number; hint?: string }[] }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="space-y-2">
      {rows.map((r, i) => (
        <div key={i} className="grid grid-cols-[minmax(0,8.5rem)_1fr_4.5rem] items-center gap-3">
          <span className="lcd truncate text-[12px]">{r.label}</span>
          <div className="h-2 overflow-hidden rounded-full bg-panel-2" aria-hidden>
            <div className="h-full rounded-full bg-accent" style={{ width: `${Math.max(3, (r.value / max) * 100)}%` }} />
          </div>
          <span className="lcd text-right text-[11px] text-faint">{r.hint}</span>
        </div>
      ))}
    </div>
  );
}

/**
 * An alert as an air-traffic flight strip: a severity bar, the ATT&CK technique as its callsign,
 * the route it is flying, and its count and age in their own boxes on the right.
 */
export function Strip({ a, fresh, onOpen, absolute, route, compact }: { a: Alert; fresh?: boolean; onOpen: (a: Alert) => void; absolute?: boolean; route?: string; compact?: boolean }) {
  const handled = (a.status ?? "open") !== "open";
  return (
    <button
      onClick={() => onOpen(a)}
      className={`strip ${fresh ? "row-new" : ""} ${handled ? "strip-handled" : ""}`}
      style={{ ["--c" as string]: LAMP[a.severity] }}
      aria-label={`${a.severity} alert: ${a.title}, ${a.mitre.id}${a.count > 1 ? `, ${a.count} times` : ""}${handled ? `, ${a.status}` : ""}`}
    >
      <span className="strip-call">
        <span className="lcd whitespace-nowrap text-[10.5px] font-semibold">{a.mitre.id}</span>
        <span className={`text-[10.5px] font-semibold uppercase tracking-wider ${a.severity === "critical" ? "blink" : ""}`} style={{ color: a.severity === "low" ? "var(--muted)" : "var(--c)" }}>
          {a.severity}
        </span>
      </span>
      <span className="strip-body">
        <span className={`block font-medium ${compact ? "line-clamp-2 text-[13px] leading-snug" : "truncate text-sm"}`}>{a.title}</span>
        <span className="lcd mt-0.5 block truncate text-[10.5px] text-faint">{route ?? `${a.src} → ${a.dst}`}</span>
      </span>
      <span className="strip-box">
        <span className="lcd text-[12px] font-medium">{a.count > 1 ? `×${a.count}` : "×1"}</span>
        <span className="text-[10px] text-faint">{absolute ? clock(a.firstSeen) : ago(a.lastSeen)}</span>
      </span>
    </button>
  );
}

export function AlertRow(props: { a: Alert; fresh?: boolean; onOpen: (a: Alert) => void; absolute?: boolean }) {
  return (
    <li>
      <Strip {...props} />
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
  tls_fingerprint: ["Find the process behind the connection on that host (EDR, or ss -tp / netstat -b).", "Search for the same JA4 across the estate: one machine or many?", "Block the destination, and add the JA4 to a rule if it is confirmed malicious."],
  rule: ["Read the rule's message and the matched value in the evidence.", "Check whether the match is expected for this host before escalating.", "Tune or disable the rule on the Rules page if it is noisy."],
  anomaly: ["Confirm with the host owner whether the transfer is expected.", "Check the destination's reputation and the data involved.", "Tune the anomaly threshold if this is normal for your network."],
};

/** Everything about one alert, with the triage controls. Used in the inspector and in dialogs. */
export function AlertBody({ alert, onChange }: { alert: Alert; onChange?: (a: Alert) => void }) {
  const [a, setA] = useState(alert);
  const [note, setNote] = useState(alert.note ?? "");
  const [err, setErr] = useState<string | null>(null);
  const actions = useActions();
  useEffect(() => {
    setA(alert);
    setNote(alert.note ?? "");
  }, [alert]);

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
    <div>
      <SevBadge s={a.severity} />
      <h2 className="mt-2 text-lg font-semibold leading-snug">{a.title}</h2>
      <p className="mt-1.5 text-sm leading-relaxed text-muted">{a.description}</p>

      {actions.replay && (
        <div className="mt-3 flex flex-wrap gap-2">
          <button className="btn btn-warn h-8" onClick={() => actions.replay!(a)} disabled={!actions.canReplay?.(a)} title={actions.canReplay?.(a) ? "Play this incident back on the scope" : "Older than the five minutes the recorder keeps"}>
            <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
              <path d="M3 12a9 9 0 1 0 3-6.7M3 4v5h5" />
            </svg>
            Replay this incident
          </button>
        </div>
      )}

      <a className="screen mt-4 block px-3 py-2.5 text-sm hover:underline" href={/^T\d/.test(a.mitre.id) ? `https://attack.mitre.org/techniques/${a.mitre.id.replace(".", "/")}/` : undefined} target="_blank" rel="noreferrer">
        <span className="silk block">MITRE ATT&amp;CK, {a.mitre.tactic}</span>
        <span className="lcd text-accent">{a.mitre.id}</span> {a.mitre.name}
      </a>

      <dl className="mt-3 grid grid-cols-2 gap-2 text-sm">
        {[
          ["Source", a.src],
          ["Target", a.dst],
          ["First seen", clock(a.firstSeen)],
          ["Last seen", `${clock(a.lastSeen)} (${a.count}×)`],
        ].map(([k, v]) => (
          <div key={k} className="screen px-3 py-2">
            <dt className="silk">{k}</dt>
            <dd className="lcd mt-0.5 break-all text-[11.5px]">{v}</dd>
          </div>
        ))}
      </dl>

      <h3 className="label mt-5">Evidence</h3>
      <table className="mt-1 w-full text-sm">
        <tbody>
          {Object.entries(a.evidence).map(([k, v]) => (
            <tr key={k} className="border-t border-line">
              <td className="py-1.5 pr-4 text-muted">{k.replace(/([A-Z])/g, " $1").toLowerCase()}</td>
              <td className="lcd break-all py-1.5 text-right text-[11.5px]">{String(v)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3 className="label mt-5">What to do</h3>
      <ol className="mt-1.5 list-decimal space-y-1.5 pl-5 text-sm text-muted">
        {(NEXT_STEPS[a.type] ?? []).map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ol>

      <div className="mt-5 border-t border-line pt-4">
        <div className="flex items-center justify-between">
          <span className="label">Triage</span>
          <span className="text-xs capitalize text-muted">Status: {a.status ?? "open"}</span>
        </div>
        <textarea className="field mt-2 h-20" placeholder="Add a note for the team (optional)" value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} />
        <div className="mt-2 flex flex-wrap gap-2">
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
    </div>
  );
}

export function AlertDrawer({ alert, onClose, onChange }: { alert: Alert; onClose: () => void; onChange?: (a: Alert) => void }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex justify-end p-2" role="dialog" aria-modal="true" aria-label={alert.title}>
      <button className="absolute inset-0 bg-black/40" aria-label="Close" onClick={onClose} />
      <aside className="panel rise scroll-y relative h-full w-full max-w-md !bg-panel-solid p-5">
        <button className="btn absolute right-3 top-3 h-8 px-2.5" onClick={onClose} aria-label="Close panel">
          ✕
        </button>
        <AlertBody alert={alert} onChange={onChange} />
      </aside>
    </div>
  );
}
