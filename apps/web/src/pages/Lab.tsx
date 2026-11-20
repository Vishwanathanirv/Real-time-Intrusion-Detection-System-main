import { Plain } from "../actions";
import { useEffect, useRef, useState } from "react";
import { ATTACK_LABELS, ATTACKS, DEFAULT_CONFIG, KNOBS, type AttackKind, type WhatIfResult } from "@packeteye/core";
import { api } from "../lib";

const CALLSIGN: Record<AttackKind, string> = { port_scan: "T1046", host_sweep: "T1018", syn_flood: "T1498", brute_force: "T1110", dns_tunnel: "T1071.4", beaconing: "T1071.1", exfiltration: "TA0010", tls_c2: "T1573" };

const secs = (ms: number) => (ms < 1000 ? `${(ms / 1000).toFixed(2)} s` : ms < 60_000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.floor(ms / 60_000)} min ${Math.round((ms % 60_000) / 1000)} s`);

/** Runs scenarios in a worker; only the newest answer is kept. */
function useWhatIf(kind: AttackKind, stretch: number, threshold: number) {
  const worker = useRef<Worker | null>(null);
  const seq = useRef(0);
  const [result, setResult] = useState<WhatIfResult | null>(null);
  const [busy, setBusy] = useState(true);
  useEffect(() => {
    const w = new Worker(new URL("../lab.worker.ts", import.meta.url), { type: "module" });
    w.onmessage = (e: MessageEvent<{ id: number; result: WhatIfResult }>) => {
      if (e.data.id !== seq.current) return;
      setResult(e.data.result);
      setBusy(false);
    };
    worker.current = w;
    return () => w.terminate();
  }, []);
  useEffect(() => {
    setBusy(true);
    const id = ++seq.current;
    const t = setTimeout(() => worker.current?.postMessage({ id, input: { kind, stretch, threshold } }), 220);
    return () => clearTimeout(t);
  }, [kind, stretch, threshold]);
  return { result, busy };
}

/** The attack's packets per second across the run, the moment it was caught, and every alert. */
function Trace({ r }: { r: WhatIfResult }) {
  const W = 640;
  const H = 120;
  const n = r.rate.length;
  const max = Math.max(1, ...r.rate);
  const x = (ms: number) => (ms / (n * 1000)) * W;
  const d = r.rate.map((v, i) => `${i ? "L" : "M"}${((i / Math.max(1, n - 1)) * W).toFixed(1)},${(H - 18 - Math.sqrt(v / max) * (H - 38)).toFixed(1)}`).join(" ");
  const caught = r.timeToDetectMs !== null ? x(r.leadMs + r.timeToDetectMs) : null;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="block w-full" role="img" aria-label={`Attack traffic over ${secs(r.windowMs)}${r.detected ? `, caught after ${secs(r.timeToDetectMs ?? 0)}` : ", never caught"}`}>
      <rect x={x(r.leadMs)} y={0} width={Math.max(2, x(r.attackSpanMs))} height={H - 18} fill="var(--bad)" fillOpacity={0.06} />
      <path d={`${d} L${W},${H - 18} L0,${H - 18} Z`} fill="var(--bad)" fillOpacity={0.18} />
      <path d={d} fill="none" stroke="var(--bad)" strokeWidth={1.6} strokeLinejoin="round" />
      {r.alerts.map((a, i) => (
        <line key={i} x1={x(r.leadMs + a.atMs)} x2={x(r.leadMs + a.atMs)} y1={14} y2={H - 18} stroke={a.caught ? "var(--accent)" : "var(--warn)"} strokeDasharray="3 3" />
      ))}
      {caught !== null && (
        <g transform={`translate(${caught} 0)`}>
          <line y1={0} y2={H - 18} stroke="var(--accent)" strokeWidth={2.5} />
          <rect x={caught > W - 90 ? -86 : 4} y={0} width={82} height={16} rx={3} fill="var(--accent)" />
          <text x={caught > W - 90 ? -45 : 45} y={11.5} textAnchor="middle" fontSize={10} fontWeight={700} fill="var(--accent-ink)" className="lcd">
            CAUGHT
          </text>
        </g>
      )}
      <text x={4} y={H - 3} fontSize={10} fill="var(--faint)" className="lcd">
        0 s
      </text>
      <text x={W - 4} y={H - 3} fontSize={10} textAnchor="end" fill="var(--faint)" className="lcd">
        {secs(r.windowMs)}
      </text>
    </svg>
  );
}

/**
 * The what-if lab: pick an attack, slow the attacker down, move one detector's threshold, and see
 * whether it is still caught and how much noise the setting makes. Every run is a real replay
 * through an isolated copy of the sensor, in a background thread.
 */
export function Lab({ live }: { live: boolean }) {
  const [kind, setKind] = useState<AttackKind>("brute_force");
  const knob = KNOBS[kind];
  const [stretch, setStretch] = useState(1);
  const [threshold, setThreshold] = useState(knob.get(DEFAULT_CONFIG));
  const [launched, setLaunched] = useState<string | null>(null);
  const { result, busy } = useWhatIf(kind, stretch, threshold);
  const pick = (k: AttackKind) => {
    setKind(k);
    setThreshold(KNOBS[k].get(DEFAULT_CONFIG));
  };
  const fresh = result && result.kind === kind && result.stretch === stretch && result.threshold === threshold;
  const r = result;
  const def = knob.get(DEFAULT_CONFIG);

  async function runLive() {
    try {
      await api("/api/attacks", { method: "POST", json: { kind, stretch } });
      setLaunched(`${ATTACK_LABELS[kind]} launched on the live scope${stretch > 1 ? `, ${stretch}× slower` : ""}. Close the lab to watch it.`);
    } catch (e) {
      setLaunched((e as Error).message);
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="display pr-12 text-[1.6rem] font-bold leading-tight">What-if lab</h1>
        <p className="mt-2 max-w-2xl text-[0.95rem] text-muted">Would PacketEye still catch it if the attacker were patient, or if you tuned a detector? Pick an attack, slow it down, move the threshold. Each change replays the attack through a separate copy of the sensor, then runs the same clean traffic again to count false alarms.</p>
        <Plain className="mt-3 max-w-2xl">A threshold is the line a detector draws: 'more than this many tries is an attack'. Set it low and you catch more attackers, but also more innocent people. Patient attackers try to stay under it.</Plain>
      </div>

      <div role="radiogroup" aria-label="Attack" className="flex flex-wrap gap-1.5">
        {ATTACKS.map((k) => (
          <button key={k} role="radio" aria-checked={k === kind} onClick={() => pick(k)} className={`chip ${k === kind ? "chip-on" : ""}`}>
            <span className="lcd text-[10px] opacity-70">{CALLSIGN[k]}</span>
            {ATTACK_LABELS[k]}
          </button>
        ))}
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,19rem)_1fr]">
        <div className="space-y-5">
          <label className="block">
            <span className="flex items-baseline justify-between">
              <span className="label">Attacker patience</span>
              <span className="lcd text-sm">{stretch === 1 ? "full speed" : `${stretch}× slower`}</span>
            </span>
            <input type="range" className="dial mt-2" min={1} max={30} step={1} value={stretch} onChange={(e) => setStretch(Number(e.target.value))} aria-label="Attacker patience: how many times slower" />
            <span className="mt-1 block text-xs text-faint">"Low and slow": the same attack, spread over more time.</span>
          </label>
          <label className="block">
            <span className="flex items-baseline justify-between gap-3">
              <span className="label">{knob.label}</span>
              <span className="lcd text-sm">{threshold}</span>
            </span>
            <input type="range" className="dial mt-2" min={knob.min} max={knob.max} step={knob.step} value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} aria-label={`Threshold: ${knob.label}`} />
            <span className="mt-1 flex justify-between text-xs text-faint">
              <span>{knob.unit}</span>
              <button className="underline underline-offset-2 hover:text-ink" onClick={() => setThreshold(def)} disabled={threshold === def}>
                default {def}
              </button>
            </span>
            <span className="mt-2 block text-xs leading-relaxed text-muted">{knob.hint}</span>
          </label>
          <div className="space-y-2 border-t border-line pt-4">
            <button className="btn btn-accent w-full justify-center" onClick={runLive} disabled={!live}>
              Run it on the live scope
            </button>
            <p className="text-xs text-faint">Launches the same attack, at this speed, against the live sensor (which keeps its default thresholds).</p>
            {launched && (
              <p className="text-xs text-muted" aria-live="polite">
                {launched}
              </p>
            )}
          </div>
        </div>

        <div className={`lab-result ${fresh ? "" : "is-busy"}`} aria-busy={busy}>
          {!r ? (
            <div className="space-y-3" aria-label="Running the scenario">
              <div className="skeleton h-14 w-2/3" />
              <div className="skeleton h-28" />
              <div className="skeleton h-10 w-1/2" />
            </div>
          ) : (
            <>
              <div className="flex flex-wrap items-end justify-between gap-3" aria-live="polite">
                <div>
                  <div className="silk">{busy ? "Re-running…" : "Verdict"}</div>
                  <div className={`verdict ${r.detected ? "text-accent" : "text-bad"}`}>{r.detected ? `Caught in ${secs(r.timeToDetectMs ?? 0)}` : "Slipped through"}</div>
                </div>
                <dl className="flex gap-5 text-right">
                  <div>
                    <dt className="silk">Attack ran for</dt>
                    <dd className="lcd">{secs(r.attackSpanMs)}</dd>
                  </div>
                  <div>
                    <dt className="silk">Packets</dt>
                    <dd className="lcd">{r.attackPackets.toLocaleString("en-IN")}</dd>
                  </div>
                  <div>
                    <dt className="silk">False alarms</dt>
                    <dd className={`lcd ${r.falseAlarms.length ? "text-warn" : ""}`}>{r.falseAlarms.length}</dd>
                  </div>
                </dl>
              </div>
              <div className="screen mt-4 p-3">
                <Trace r={r} />
              </div>
              <p className="mt-4 text-sm leading-relaxed text-muted">
                {r.detected
                  ? `${r.label}${r.stretch > 1 ? ` at ${r.stretch}× slower` : ""} is still caught with the threshold at ${r.threshold}.`
                  : `${r.label}${r.stretch > 1 ? ` at ${r.stretch}× slower` : ""} gets past a threshold of ${r.threshold}: no detector that is meant to catch it fired.`}{" "}
                {r.falseAlarms.length
                  ? `But on the same clean traffic this setting raises ${r.falseAlarms.length} false alarm${r.falseAlarms.length > 1 ? "s" : ""} (${[...new Set(r.falseAlarms.map((a) => a.type.replace(/_/g, " ")))].join(", ")}). Someone would have to look at each one.`
                  : "And it raises no false alarms on the same clean traffic."}
              </p>
              {r.alerts.length > 0 && (
                <ul className="mt-3 space-y-1.5" aria-label="Alerts raised in the scenario">
                  {r.alerts.slice(0, 6).map((a, i) => (
                    <li key={i} className="flex items-center gap-3 text-sm">
                      <span className="lcd w-20 shrink-0 text-right text-[11px] text-faint">+{secs(Math.max(0, a.atMs))}</span>
                      <span className={`led`} style={{ ["--c" as string]: a.caught ? "var(--accent)" : "var(--warn)" }} aria-hidden />
                      <span className="min-w-0 truncate">{a.title}</span>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
