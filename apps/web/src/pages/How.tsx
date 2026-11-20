import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { flushSync } from "react-dom";
import { Link, useNavigate } from "react-router";
import type { Trace } from "../how-data";
import { api, bytes } from "../lib";
import { Strip } from "../ui";

/** The five stages, as range rings from the edge of the scope to its centre. */
const STAGES = [
  { key: "capture", name: "Capture", r: 500, line: "Raw bytes off the wire" },
  { key: "decode", name: "Decode", r: 395, line: "Bytes become a packet" },
  { key: "flows", name: "Flow", r: 290, line: "Packets become a conversation" },
  { key: "detect", name: "Detect", r: 185, line: "Rules and machine learning judge it" },
  { key: "alert", name: "Alert", r: 0, line: "A strip on the board" },
] as const;

const LAYER_COLOUR = ["var(--node-ext)", "var(--accent)", "var(--warn)", "var(--bad)"];
const BEARING = (-38 * Math.PI) / 180;

function useTrace() {
  const [trace, setTrace] = useState<Trace | null>(null);
  useEffect(() => {
    const w = new Worker(new URL("../core.worker.ts", import.meta.url), { type: "module" });
    w.onmessage = (e: MessageEvent<{ result: Trace }>) => setTrace(e.data.result);
    w.postMessage({ id: 1, op: "trace" });
    return () => w.terminate();
  }, []);
  return trace;
}

/** Moves between stages with a view transition where the browser has them and motion is welcome. */
function useStep(): [number, (n: number) => void] {
  const [step, setStep] = useState(0);
  const go = useCallback((n: number) => {
    const next = Math.max(0, Math.min(STAGES.length - 1, n));
    const doc = document as Document & { startViewTransition?: (cb: () => void) => unknown };
    if (doc.startViewTransition && !matchMedia("(prefers-reduced-motion: reduce)").matches) doc.startViewTransition(() => flushSync(() => setStep(next)));
    else setStep(next);
  }, []);
  return [step, go];
}

/** The scope with the stages as rings; the sample packet sinks inward one ring per stage. */
function StageScope({ step, onPick }: { step: number; onPick: (n: number) => void }) {
  const r = STAGES[step].r;
  return (
    <svg viewBox="-600 -600 1200 1200" className="how-scope" role="group" aria-label="The pipeline as range rings: capture at the edge, the alert at the centre">
      <defs>
        <radialGradient id="how-glow">
          <stop offset="0" stopColor="var(--accent)" stopOpacity="0.14" />
          <stop offset="1" stopColor="var(--accent)" stopOpacity="0.02" />
        </radialGradient>
      </defs>
      <circle r={560} fill="url(#how-glow)" stroke="var(--line)" />
      <line x1={-560} x2={560} y1={0} y2={0} stroke="var(--line)" strokeDasharray="1 8" />
      <line y1={-560} y2={560} x1={0} x2={0} stroke="var(--line)" strokeDasharray="1 8" />
      <g className="sweep" aria-hidden>
        <path d="M0 0 L560 0 A560 560 0 0 0 395.98 -395.98 Z" fill="var(--accent)" fillOpacity={0.06} />
      </g>
      {STAGES.map((s, i) => {
        const state = i < step ? "past" : i === step ? "now" : "next";
        return (
          <g key={s.key} className="cursor-pointer" onClick={() => onPick(i)} role="button" tabIndex={0} aria-label={`Stage ${i + 1}: ${s.name}`} aria-current={i === step ? "step" : undefined} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onPick(i)}>
            {s.r > 0 ? (
              <>
                <circle r={s.r} fill="none" stroke="transparent" strokeWidth={60} />
                <circle r={s.r} fill="none" className={`how-ring how-ring-${state}`} />
                <text y={-s.r - 14} textAnchor="middle" fontSize={26} fontWeight={700} letterSpacing="0.12em" className={`how-label how-label-${state}`}>
                  {String(i + 1).padStart(2, "0")} · {s.name.toUpperCase()}
                </text>
              </>
            ) : (
              <>
                <circle r={60} fill="transparent" />
                <circle r={12} className={`how-core how-core-${state}`} />
                <text y={92} textAnchor="middle" fontSize={26} fontWeight={700} letterSpacing="0.12em" className={`how-label how-label-${state}`}>
                  05 · ALERT
                </text>
              </>
            )}
          </g>
        );
      })}
      {/* The sample packet. */}
      <g className="how-blip" style={{ transform: `translate(${Math.cos(BEARING) * r}px, ${Math.sin(BEARING) * r}px)` }} aria-hidden>
        {step === 4 ? (
          <>
            <circle r={18} fill="var(--bad)" />
            <circle r={18} fill="none" stroke="var(--bad)" strokeWidth={3} className="alarm" style={{ ["--r0" as string]: "18px" }} />
            <path d="M-40 -22 L-40 -40 L-22 -40 M22 -40 L40 -40 L40 -22 M40 22 L40 40 L22 40 M-22 40 L-40 40 L-40 22" fill="none" stroke="var(--bad)" strokeWidth={4} />
          </>
        ) : (
          <>
            <circle r={26} fill="var(--accent)" fillOpacity={0.18} />
            <circle r={11} fill="var(--accent)" />
          </>
        )}
      </g>
    </svg>
  );
}

function Hex({ trace, hi }: { trace: Trace; hi?: [number, number] }) {
  const layerOf = (i: number) => trace.layers.findIndex((l) => i >= l.from && i < l.to);
  const shown = trace.frame.slice(0, 96);
  return (
    <div className="hex lcd" aria-label={`The first ${shown.length} of ${trace.frame.length} bytes of the frame`}>
      {shown.map((b, i) => {
        const on = hi ? i >= hi[0] && i < hi[1] : true;
        return (
          <span key={i} style={{ color: LAYER_COLOUR[layerOf(i)], opacity: on ? 1 : 0.22 }}>
            {b.toString(16).padStart(2, "0")}
          </span>
        );
      })}
      {trace.frame.length > shown.length && <span className="col-span-full text-faint">… {trace.frame.length - shown.length} more bytes of TLS hello</span>}
    </div>
  );
}

function Verdict({ fired, children }: { fired: boolean; children: ReactNode }) {
  return <span className={`how-verdict ${fired ? "is-fired" : ""}`}>{children}</span>;
}

function Stage({ step, trace }: { step: number; trace: Trace }) {
  const [hi, setHi] = useState<[number, number] | undefined>();
  const navigate = useNavigate();
  const p = trace.packet;
  const f = trace.flow;
  if (step === 0)
    return (
      <>
        <p className="how-lead">A network card sees every frame that passes. PacketEye reads them from tcpdump, an uploaded capture or its simulator. This is one, exactly as it arrived: {trace.frame.length} bytes from {p.src}, mixed in with {trace.background.toLocaleString("en-IN")} packets of ordinary office traffic.</p>
        <Hex trace={trace} />
        <ul className="mt-4 grid gap-2 sm:grid-cols-2">
          {trace.layers.map((l, i) => (
            <li key={l.name} className="flex gap-2.5 text-sm">
              <span className="mt-1.5 h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: LAYER_COLOUR[i] }} aria-hidden />
              <span>
                <strong className="font-semibold">{l.name}</strong> <span className="lcd text-[11px] text-faint">{l.to - l.from} B</span>
                <span className="block text-muted">{l.note}</span>
              </span>
            </li>
          ))}
        </ul>
      </>
    );
  if (step === 1)
    return (
      <>
        <p className="how-lead">The decoder walks the headers and keeps only what detection needs. The message itself is encrypted and is never read. Point at a field to see the bytes it came from.</p>
        <Hex trace={trace} hi={hi} />
        <dl className="mt-4 grid gap-x-4 gap-y-1 sm:grid-cols-2" onPointerLeave={() => setHi(undefined)}>
          {trace.fields.map((x) => (
            <div key={x.k} tabIndex={0} className="how-field" onPointerEnter={() => setHi([x.from, x.to])} onFocus={() => setHi([x.from, x.to])} onBlur={() => setHi(undefined)}>
              <dt className="silk">{x.k}</dt>
              <dd className="lcd break-all text-[12.5px]">{x.v}</dd>
            </div>
          ))}
        </dl>
        <p className="plain mt-4">
          <span className="plain-mark" aria-hidden>
            ?
          </span>
          <span>
            <strong className="font-semibold">JA4</strong> sums up how this app says hello: TLS version, how many ciphers and extensions it offers, and a hash of them. Every Chrome on the network says hello the same way. This one doesn't match anything else here.
          </span>
        </p>
      </>
    );
  if (step === 2)
    return (
      <>
        <p className="how-lead">Packets are grouped into flows: every packet between the same two addresses and ports is one conversation. When it ends, it becomes a row of numbers that describe its shape.</p>
        <dl className="how-flow">
          {[
            ["Conversation", `${f.src}:${f.sport} → ${f.dst}:${f.dport}`],
            ["Packets", `${f.packets} (${f.fwdPackets} out, ${f.bwdPackets} back)`],
            ["Bytes", `${bytes(f.bytes)} (${bytes(f.fwdBytes)} out)`],
            ["Lasted", `${(f.last - f.start).toFixed(0)} ms`],
            ["Handshake", f.established ? "completed" : "never completed"],
          ].map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd className="lcd">{v}</dd>
            </div>
          ))}
        </dl>
        <h3 className="label mt-5">Its ten features</h3>
        <div className="mt-2 grid gap-1.5">
          {trace.features.map((x) => (
            <div key={x.name} className="grid grid-cols-[9rem_1fr_4rem] items-center gap-3 text-[12px]">
              <span className="lcd truncate text-muted">{x.name}</span>
              <span className="h-1.5 overflow-hidden rounded-full bg-panel-2" aria-hidden>
                <span className="block h-full rounded-full bg-accent" style={{ width: `${Math.max(3, Math.min(100, (x.value / (x.name === "bytes_per_packet" ? 1500 : x.name.startsWith("log") ? 16 : 3)) * 100))}%` }} />
              </span>
              <span className="lcd text-right">{Number.isInteger(x.value) ? x.value : x.value.toFixed(2)}</span>
            </div>
          ))}
        </div>
      </>
    );
  if (step === 3) {
    const rare = trace.alerts.find((a) => a.type === "tls_fingerprint");
    const ml = trace.score >= trace.threshold;
    return (
      <>
        <p className="how-lead">Three different judges look at the same traffic. Each one catches things the others miss.</p>
        <ol className="how-judges">
          <li>
            <div className="flex items-center justify-between gap-3">
              <strong>Behaviour</strong>
              <Verdict fired={Boolean(rare)}>{rare ? "Fired" : "Quiet"}</Verdict>
            </div>
            <p>Eight detectors count and time things: ports tried, logins per minute, regular call-home timers, and how many hosts share each TLS fingerprint. {rare ? `This fingerprint is used by ${rare.evidence.hostsWithFingerprint} host on the network, so it is rare.` : ""}</p>
          </li>
          <li>
            <div className="flex items-center justify-between gap-3">
              <strong>Signatures</strong>
              <Verdict fired={trace.ruleHits.length > 0}>{trace.ruleHits.length ? "Matched" : "No match"}</Verdict>
            </div>
            <p>
              {trace.rulesLoaded} hand-written rules in Suricata syntax. {trace.ruleHits.length ? `This connection matched “${trace.ruleHits[0]}”.` : "None of them describe this connection."}
            </p>
          </li>
          <li>
            <div className="flex items-center justify-between gap-3">
              <strong>Machine learning</strong>
              <Verdict fired={ml}>{ml ? "Unusual" : "Looks normal"}</Verdict>
            </div>
            <p>An isolation forest trained only on normal traffic scores how unlike normal each flow is. It has never seen an attack.</p>
            <div className="how-gauge" role="meter" aria-valuemin={0} aria-valuemax={1} aria-valuenow={+trace.score.toFixed(2)} aria-label="Anomaly score">
              <span className="how-gauge-fill" style={{ width: `${trace.score * 100}%` }} />
              <span className="how-gauge-cut" style={{ left: `${trace.threshold * 100}%` }} />
            </div>
            <div className="lcd mt-1 flex justify-between text-[11px] text-faint">
              <span>score {trace.score.toFixed(2)}</span>
              <span>alerts above {trace.threshold}</span>
            </div>
          </li>
        </ol>
        {!ml && <p className="plain mt-4"><span className="plain-mark" aria-hidden>!</span><span>The model alone would have missed this implant: its flow is small and short, like a normal web request. The fingerprint is what gives it away. That is why PacketEye never relies on one method.</span></p>}
      </>
    );
  }
  return (
    <>
      <p className="how-lead">Repeats are folded into one alert with a count, mapped to MITRE ATT&amp;CK, and put on the board as a flight strip. On the scope, the implant's host and its link to the internet turn coral.</p>
      <div className="strip-board">
        {trace.alerts.slice(0, 3).map((a) => (
          <Strip key={a.id} a={{ ...a, status: "open" }} absolute onOpen={() => {}} />
        ))}
      </div>
      <div className="mt-5 flex flex-wrap gap-2">
        <button
          className="btn btn-accent"
          onClick={() => {
            void api("/api/attacks", { method: "POST", json: { kind: "tls_c2" } }).catch(() => {});
            navigate("/");
          }}
        >
          Launch this implant on the live scope
        </button>
        <Link to="/lab" className="btn">
          Try to sneak it past in the what-if lab
        </Link>
      </div>
    </>
  );
}

/**
 * How it works: one real implant packet followed from the wire to the alert board, on a scope whose
 * range rings are the stages of the pipeline.
 */
export function How() {
  const trace = useTrace();
  const [step, go] = useStep();
  const navigate = useNavigate();
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    document.title = "How it works · PacketEye";
    return () => {
      document.title = "PacketEye · Sonar for your network";
    };
  }, []);
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName) || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "ArrowRight") go(step + 1);
      else if (e.key === "ArrowLeft") go(step - 1);
      else if (e.key >= "1" && e.key <= "5") go(Number(e.key) - 1);
      else if (e.key === "Escape") navigate("/");
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [step, go, navigate]);
  useEffect(() => {
    panel.current?.scrollTo({ top: 0 });
  }, [step]);
  const s = STAGES[step];
  return (
    <main className="how scroll-y h-dvh">
      <header className="how-top">
        <Link to="/" className="flex items-center gap-2.5" aria-label="PacketEye: back to the live scope">
          <img src="/favicon.svg" alt="" className="h-7 w-7" />
          <span className="display text-lg font-bold">PacketEye</span>
        </Link>
        <span className="silk hidden sm:inline">How it works</span>
        <Link to="/" className="btn ml-auto h-8">
          Back to the scope
        </Link>
      </header>
      <p className="how-idea">
        <span className="tape-badge !bg-accent">KEY IDEA</span> PacketEye never reads what's inside a message. It watches the <em>shape</em> of conversations: who talks to whom, how often, how much, how regularly, and how each app says hello. Attacks have a shape, even when they're encrypted.
      </p>
      <div className="how-grid">
        <div className="how-left">
          <StageScope step={step} onPick={go} />
        </div>
        <section className="how-panel" ref={panel} aria-live="polite" aria-labelledby="how-stage-title">
          <div className="silk lcd">
            STAGE {step + 1} OF 5 · {s.line.toUpperCase()}
          </div>
          <h1 id="how-stage-title" className="display mt-1 text-[clamp(1.7rem,3.6vw,2.6rem)] font-bold leading-none">
            {s.name}
          </h1>
          <div className="mt-4" style={{ viewTransitionName: "how-stage" }}>
            {trace ? (
              <Stage step={step} trace={trace} />
            ) : (
              <div className="space-y-3" aria-label="Preparing the sample packet">
                <div className="skeleton h-12" />
                <div className="skeleton h-40" />
                <div className="skeleton h-16 w-2/3" />
              </div>
            )}
          </div>
          <nav className="how-nav" aria-label="Stages">
            <button className="btn" onClick={() => go(step - 1)} disabled={step === 0} aria-label="Previous stage">
              ←
            </button>
            <ol className="flex flex-1 justify-center gap-1.5">
              {STAGES.map((x, i) => (
                <li key={x.key}>
                  <button className={`how-dot ${i === step ? "is-on" : i < step ? "is-past" : ""}`} onClick={() => go(i)} aria-label={`${i + 1}. ${x.name}`} aria-current={i === step ? "step" : undefined} />
                </li>
              ))}
            </ol>
            <button className="btn btn-accent" onClick={() => (step === 4 ? navigate("/") : go(step + 1))} aria-label={step === 4 ? "Finish and go to the live scope" : "Next stage"}>
              {step === 4 ? "To the scope" : `Next: ${STAGES[step + 1].name}`} →
            </button>
          </nav>
        </section>
      </div>
    </main>
  );
}
