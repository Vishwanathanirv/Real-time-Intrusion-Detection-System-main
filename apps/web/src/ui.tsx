import { useEffect, useState, type ReactNode } from "react";
import { ago, api, clock, type Alert, type Severity } from "./lib";

/** Lamp colour per severity: the LEDs on the front of the box. */
const LAMP: Record<Severity, string> = { low: "var(--led-green)", medium: "var(--led-amber)", high: "var(--led-red)", critical: "var(--led-red)" };

export function SevBadge({ s }: { s: Severity }) {
  return (
    <span className="inline-flex items-center gap-2 font-display text-[13px] font-semibold capitalize" style={{ color: s === "low" ? "var(--muted)" : s === "medium" ? "var(--warn)" : "var(--bad)" }}>
      <span className={`led ${s === "critical" ? "blink" : ""}`} style={{ ["--c" as string]: LAMP[s] }} aria-hidden />
      {s}
    </span>
  );
}

/** A readout: a small inset screen with the figure in phosphor, and its name printed beneath. */
export function Kpi({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  const alarm = tone === "bad";
  return (
    <div className="panel px-3 pb-3 pt-4">
      <div className="screen px-3 py-2.5">
        <div className="lcd whitespace-nowrap text-[clamp(1.2rem,1.9vw,1.7rem)] leading-none tabular-nums" style={alarm ? { color: "var(--led-red)", textShadow: "0 0 8px rgba(255,59,59,.6)" } : undefined}>
          {value}
        </div>
      </div>
      <div className="silk mt-2 px-0.5 text-ink">{label}</div>
      {sub && <div className="mt-0.5 px-0.5 text-xs text-faint">{sub}</div>}
    </div>
  );
}

export function Panel({ title, action, children, className = "" }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between gap-3 px-5 pb-2 pt-3.5">
          <h2 className="font-display text-[1.02rem] font-semibold tracking-[0.01em] [text-shadow:0_1px_0_var(--sheen)]">{title}</h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

/** Packets per second over the last two minutes, traced on a scope screen, with red marks where alerts fired. */
export function TrafficChart({ series }: { series: { t: number; packets: number; alerts: number }[] }) {
  const W = 600;
  const H = 140;
  const max = Math.max(10, ...series.map((s) => s.packets));
  const x = (i: number) => (i / Math.max(1, series.length - 1)) * W;
  const y = (v: number) => H - 6 - (v / max) * (H - 18);
  const d = series.map((s, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(s.packets).toFixed(1)}`).join(" ");
  return (
    <div className="screen mx-4 mb-4 overflow-hidden">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="block h-40 w-full" role="img" aria-label="Packets per second">
        {Array.from({ length: 11 }, (_, i) => (
          <line key={`v${i}`} x1={(i / 10) * W} x2={(i / 10) * W} y1={0} y2={H} stroke="var(--screen-line)" vectorEffect="non-scaling-stroke" />
        ))}
        {[0.25, 0.5, 0.75].map((g) => (
          <line key={g} x1={0} x2={W} y1={y(max * g)} y2={y(max * g)} stroke="var(--screen-line)" vectorEffect="non-scaling-stroke" />
        ))}
        {series.map((s, i) => (s.alerts ? <line key={s.t} x1={x(i)} x2={x(i)} y1={0} y2={H} stroke="var(--led-red)" strokeWidth={2} opacity={0.75} vectorEffect="non-scaling-stroke" /> : null))}
        <path d={d} fill="none" stroke="var(--phosphor)" strokeOpacity={0.35} strokeWidth={6} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
        <path d={d} fill="none" stroke="var(--phosphor)" strokeWidth={1.6} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
      </svg>
      <span className="lcd pointer-events-none absolute left-2.5 top-1.5 text-[11px] opacity-80">{Math.round(max).toLocaleString()} pkt/s</span>
    </div>
  );
}

/** A segmented meter per row, like the level bars on a hardware display. */
export function Bars({ rows }: { rows: { label: ReactNode; value: number; hint?: string }[] }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  const SEG = 16;
  return (
    <div className="screen space-y-2 px-3 py-3">
      {rows.map((r, i) => {
        const lit = Math.max(1, Math.round((r.value / max) * SEG));
        return (
          <div key={i} className="grid grid-cols-[minmax(0,8.5rem)_1fr_4.5rem] items-center gap-3">
            <span className="lcd truncate text-[13px]">{r.label}</span>
            <div className="flex gap-[2px]" aria-hidden>
              {Array.from({ length: SEG }, (_, k) => (
                <span key={k} className="h-2.5 flex-1 rounded-[1px]" style={{ background: k < lit ? "var(--phosphor)" : "rgba(255,187,85,.1)", boxShadow: k < lit ? "0 0 4px rgba(255,187,85,.45)" : undefined }} />
              ))}
            </div>
            <span className="lcd text-right text-[12px] opacity-75">{r.hint}</span>
          </div>
        );
      })}
    </div>
  );
}

export function AlertRow({ a, fresh, onOpen, absolute }: { a: Alert; fresh?: boolean; onOpen: (a: Alert) => void; absolute?: boolean }) {
  return (
    <li>
      <button onClick={() => onOpen(a)} className={`grid w-full grid-cols-[5.5rem_1fr_auto] items-center gap-3 border-t border-line px-5 py-3 text-left hover:bg-panel-2 ${fresh ? "row-new" : ""}`}>
        <SevBadge s={a.severity} />
        <span className="min-w-0">
          <span className="block truncate text-sm">{a.title}</span>
          <span className="mt-0.5 block truncate text-xs text-faint">
            <span className="font-mono">{a.mitre.id}</span> {a.mitre.tactic}, {a.src} → {a.dst}
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
  tls_fingerprint: ["Find the process behind the connection on that host (EDR, or ss -tp / netstat -b).", "Search for the same JA4 across the estate: one machine or many?", "Block the destination, and add the JA4 to a rule if it is confirmed malicious."],
  rule: ["Read the rule's message and the matched value in the evidence.", "Check whether the match is expected for this host before escalating.", "Tune or disable the rule on the Rules page if it is noisy."],
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
          <a className="mt-2 block text-sm hover:underline" href={/^T\d/.test(a.mitre.id) ? `https://attack.mitre.org/techniques/${a.mitre.id.replace(".", "/")}/` : undefined} target="_blank" rel="noreferrer">
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
