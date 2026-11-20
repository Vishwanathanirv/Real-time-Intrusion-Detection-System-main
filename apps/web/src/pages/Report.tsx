import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { PLAIN } from "../actions";
import { clock } from "../lib";
import { hostOf, isServer, lockOn, place, ROLE } from "../map";
import { decodeReport, type Report as R } from "../report-codec";
import { NEXT_STEPS } from "../ui";

const name = (addr: string) => ROLE[hostOf(addr)] ?? addr;
const dur = (ms: number) => (ms < 60_000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.floor(ms / 60_000)} min ${Math.round((ms % 60_000) / 1000)} s`);

/** The incident on a small scope, playable frame by frame like the Rewind tape. */
function MiniScope({ report }: { report: R }) {
  const { alert, frames } = report;
  const [i, setI] = useState(0);
  const [playing, setPlaying] = useState(true);
  useEffect(() => {
    if (!playing || frames.length < 2) return;
    const id = setInterval(() => setI((x) => (x + 1) % frames.length), 450);
    return () => clearInterval(id);
  }, [playing, frames.length]);
  const seen = useMemo(() => {
    const all = new Map<string, boolean>();
    for (const f of frames) for (const n of f.graph.nodes) all.set(n.ip, n.internal);
    const ipNum = (ip: string) => ip.split(".").reduce((n, o) => n * 256 + Number(o), 0);
    const ips = [...all.entries()].map(([ip, internal]) => ({ ip, internal }));
    return {
      servers: ips.filter(isServer).map((n) => n.ip).sort((a, b) => ipNum(a) - ipNum(b)),
      workstations: ips.filter((n) => n.internal && !isServer(n)).map((n) => n.ip).sort((a, b) => ipNum(a) - ipNum(b)),
    };
  }, [frames]);
  const f = frames[i];
  const hot = new Set([hostOf(alert.src), hostOf(alert.dst)]);
  const raised = f ? f.t >= alert.firstSeen : false;
  const pos = new Map((f?.graph.nodes ?? []).map((n) => [n.ip, { ...n, ...place(n, seen) }]));
  for (const ip of hot) if (!pos.has(ip)) { const n = { ip, bytes: 0, internal: /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) }; pos.set(ip, { ...n, ...place(n, seen) }); }
  return (
    <figure className="report-scope">
      <svg viewBox="-600 -600 1200 1200" className="block w-full" role="img" aria-label={`The incident on the scope, frame ${i + 1} of ${frames.length}`}>
        <circle r={560} fill="color-mix(in oklab, var(--accent) 5%, transparent)" stroke="var(--line)" />
        {[120, 310, 500].map((r) => (
          <circle key={r} r={r} fill="none" stroke="var(--faint)" strokeOpacity={0.4} strokeWidth={1.5} />
        ))}
        <line x1={-560} x2={560} y1={0} y2={0} stroke="var(--line)" strokeDasharray="1 8" />
        <line y1={-560} y2={560} x1={0} x2={0} stroke="var(--line)" strokeDasharray="1 8" />
        {f?.graph.edges.map((e) => {
          const a = pos.get(e.src);
          const b = pos.get(e.dst);
          if (!a || !b) return null;
          const bad = raised && hot.has(e.src) && hot.has(e.dst);
          return <line key={`${e.src}>${e.dst}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={bad ? "var(--bad)" : "var(--accent)"} strokeOpacity={bad ? 0.9 : 0.3} strokeWidth={bad ? 4 : 2} />;
        })}
        {[...pos.values()].map((n) => {
          const isHot = hot.has(n.ip);
          return (
            <g key={n.ip} transform={`translate(${n.x} ${n.y})`}>
              {isHot && <path d={lockOn(26)} fill="none" stroke={raised ? "var(--bad)" : "var(--accent)"} strokeWidth={4} />}
              <circle r={isHot ? 13 : 9} fill={isHot && raised ? "var(--bad)" : n.internal ? "var(--node)" : "var(--node-ext)"} />
              {(isHot || ROLE[n.ip]) && (
                <text y={isHot ? 46 : 32} textAnchor="middle" fontSize={isHot ? 26 : 20} fontWeight={600} fill="var(--ink)" paintOrder="stroke" stroke="var(--bg)" strokeWidth={6}>
                  {ROLE[n.ip] ?? n.ip}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <figcaption className="mt-3 flex items-center gap-3">
        <button className="btn btn-warn h-8 w-8 justify-center px-0" onClick={() => setPlaying(!playing)} aria-label={playing ? "Pause the incident" : "Play the incident"}>
          <svg viewBox="0 0 24 24" className="h-4 w-4" fill="currentColor" aria-hidden>
            <path d={playing ? "M6 5h4v14H6zM14 5h4v14h-4z" : "M7 4l13 8-13 8z"} />
          </svg>
        </button>
        <input type="range" className="dial flex-1" min={0} max={Math.max(0, frames.length - 1)} value={i} onChange={(e) => { setPlaying(false); setI(Number(e.target.value)); }} aria-label="Incident frame" />
        <span className="lcd w-20 text-right text-xs text-muted">{f ? clock(f.t) : "–"}</span>
      </figcaption>
      {!frames.length && <p className="mt-2 text-xs text-faint">The scope was not recording when this alert was raised, so the report has no frames.</p>}
    </figure>
  );
}

/**
 * A shared incident report: everything about one alert, readable by someone with no PacketEye of
 * their own. It is decoded from the link's fragment, which never leaves the browser.
 */
export function Report() {
  const [state, setState] = useState<{ report?: R; error?: string }>({});
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    document.title = "Incident report · PacketEye";
    const load = () =>
      decodeReport(location.hash)
        .then((report) => setState({ report }))
        .catch(() => setState({ error: "This link doesn't contain a readable incident report. It may have been cut short when it was copied." }));
    void load();
    window.addEventListener("hashchange", load);
    return () => window.removeEventListener("hashchange", load);
  }, []);
  const r = state.report;
  const a = r?.alert;
  return (
    <main className="report scroll-y h-dvh">
      <div className="mx-auto max-w-5xl px-4 pb-16 pt-6 sm:px-8">
        <header className="flex flex-wrap items-center gap-3 border-b border-line pb-4">
          <img src="/favicon.svg" alt="" className="h-7 w-7" />
          <span className="display text-lg font-bold">PacketEye</span>
          <span className="silk">Incident report</span>
          <span className="flex w-full flex-wrap gap-2 whitespace-nowrap sm:ml-auto sm:w-auto print:hidden">
            <button className="btn h-8" onClick={() => void navigator.clipboard?.writeText(location.href).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); })}>
              {copied ? "Link copied" : "Copy link"}
            </button>
            <button className="btn h-8" onClick={() => print()} disabled={!r}>
              Save as PDF
            </button>
            <Link to="/" className="btn btn-accent h-8">
              Open the live scope
            </Link>
          </span>
        </header>

        {state.error && (
          <div className="py-20 text-center">
            <h1 className="display text-2xl font-bold">No report here</h1>
            <p className="mx-auto mt-2 max-w-md text-muted">{state.error}</p>
          </div>
        )}
        {!r && !state.error && (
          <div className="space-y-4 py-10" aria-label="Loading the report">
            <div className="skeleton h-24 w-3/4" />
            <div className="skeleton h-72" />
          </div>
        )}

        {r && a && (
          <article className="rise">
            <section className="report-head" style={{ ["--c" as string]: a.severity === "medium" ? "var(--warn)" : a.severity === "low" ? "var(--faint)" : "var(--bad)" }}>
              <div className="report-callsign lcd">{a.mitre.id}</div>
              <div className="min-w-0">
                <div className="report-stamp">{a.severity}</div>
                <h1 className="display mt-2 text-[clamp(1.5rem,4vw,2.4rem)] font-bold leading-[1.05]">{a.title}</h1>
                <p className="lcd mt-2 text-sm text-muted">
                  {name(a.src)} <span className="text-faint">→</span> {name(a.dst)}
                </p>
              </div>
            </section>

            <dl className="report-facts">
              {[
                ["Technique", `${a.mitre.name}`],
                ["Tactic", a.mitre.tactic],
                ["First seen", `${new Date(a.firstSeen).toLocaleDateString("en-GB")} ${clock(a.firstSeen)}`],
                ["Lasted", dur(a.lastSeen - a.firstSeen)],
                ["Times seen", `${a.count}×`],
                ["Status", a.status ?? "open"],
              ].map(([k, v]) => (
                <div key={k}>
                  <dt>{k}</dt>
                  <dd className="capitalize-first">{v}</dd>
                </div>
              ))}
            </dl>

            <div className="mt-8 grid gap-8 md:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
              <MiniScope report={r} />
              <div className="space-y-7">
                <section>
                  <h2 className="label">What happened</h2>
                  <p className="mt-1.5 leading-relaxed">{a.description}</p>
                  {PLAIN[a.type] && (
                    <p className="plain mt-3">
                      <span className="plain-mark" aria-hidden>?</span>
                      <span>
                        <strong className="font-semibold">In plain words: </strong>
                        {PLAIN[a.type].what} <span className="text-muted">Why it matters: {PLAIN[a.type].why}</span>
                      </span>
                    </p>
                  )}
                </section>
                <section>
                  <h2 className="label">Evidence</h2>
                  <table className="mt-1 w-full text-sm">
                    <tbody>
                      {Object.entries(a.evidence).map(([k, v]) => (
                        <tr key={k} className="border-t border-line">
                          <td className="py-1.5 pr-4 text-muted">{k.replace(/([A-Z])/g, " $1").toLowerCase()}</td>
                          <td className="lcd break-all py-1.5 text-right text-[12px]">{String(v)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </section>
                <section>
                  <h2 className="label">Recommended response</h2>
                  <ol className="mt-1.5 list-decimal space-y-1.5 pl-5 text-sm">
                    {(NEXT_STEPS[a.type] ?? []).map((s) => (
                      <li key={s}>{s}</li>
                    ))}
                  </ol>
                </section>
                {a.note && (
                  <section>
                    <h2 className="label">Analyst note</h2>
                    <blockquote className="mt-1.5 border-l-2 border-accent pl-3 text-sm">{a.note}</blockquote>
                  </section>
                )}
              </div>
            </div>
            <footer className="mt-10 border-t border-line pt-4 text-xs text-faint">
              Shared {new Date(r.createdAt).toLocaleString("en-GB")}. This report is stored entirely in its link: opening it sends nothing to any server.
            </footer>
          </article>
        )}
      </div>
    </main>
  );
}
