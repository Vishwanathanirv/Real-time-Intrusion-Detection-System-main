import { useEffect, useState } from "react";
import { api, usePoll } from "../lib";
import { Panel, SevBadge } from "../ui";
import type { Severity } from "../lib";

type RuleRow = { sid: number; rev: number; msg: string; proto: string; classtype: string | null; severity: Severity; mitre: string | null; line: number; hits: number };
type RuleView = { text: string; rules: RuleRow[] };
type RuleError = { line: number; message: string };

const EXAMPLE = `alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"TLS to a file-sharing site"; tls.sni; content:"transfer.sh"; endswith; nocase; sid:1000100; rev:1;)`;

export function Rules() {
  const { data, reload } = usePoll<RuleView>("/api/rules", 3000);
  const [text, setText] = useState<string | null>(null);
  const [errors, setErrors] = useState<RuleError[]>([]);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (text === null && data) setText(data.text);
  }, [data, text]);
  const dirty = text !== null && data !== null && text !== data.text;

  async function apply() {
    if (text === null) return;
    setBusy(true);
    setMsg(null);
    setErrors([]);
    try {
      const r = await api<RuleView>("/api/rules", { method: "PUT", json: { text } });
      setMsg(`Loaded ${r.rules.length} rule${r.rules.length === 1 ? "" : "s"}. They apply to live traffic and uploaded captures from now on.`);
      await reload();
    } catch (e) {
      const err = e as Error & { details?: { errors?: RuleError[] } };
      setErrors(err.details?.errors ?? []);
      setMsg(err.message);
    } finally {
      setBusy(false);
    }
  }

  const lines = (text ?? "").split("\n").length;
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-[1.7rem] font-bold tracking-tight">Detection rules</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted">
          Signatures in Suricata syntax run beside the behavioural detectors, so a SOC can add its own detections in a language it already knows. Match on addresses, ports and TCP flags, and on DNS names, TLS server names and JA4 fingerprints with{" "}
          <code className="font-mono text-xs">dns.query</code>, <code className="font-mono text-xs">tls.sni</code> and <code className="font-mono text-xs">ja4.hash</code>. Thresholds work the same way as in Suricata.
        </p>
      </div>
      <div className="grid gap-5 xl:grid-cols-[1.25fr_1fr]">
        <Panel
          title="Ruleset"
          action={
            <div className="flex gap-2">
              <button className="btn h-8" disabled={busy} onClick={() => setText((t) => `${(t ?? "").trimEnd()}\n${EXAMPLE}\n`)}>
                Add example
              </button>
              <button className="btn btn-accent h-8" disabled={busy || !dirty} onClick={apply}>
                {busy ? "Checking…" : "Apply"}
              </button>
            </div>
          }
        >
          <div className="flex max-h-[34rem] overflow-auto">
            <pre aria-hidden className="select-none border-r border-line px-3 py-3 text-right font-mono text-[11.5px] leading-[1.6] text-faint">
              {Array.from({ length: lines }, (_, i) => {
                const bad = errors.some((e) => e.line === i + 1);
                return (
                  <div key={i} className={bad ? "text-bad" : ""}>
                    {i + 1}
                  </div>
                );
              })}
            </pre>
            <textarea
              aria-label="Rules"
              spellCheck={false}
              wrap="off"
              className="min-h-[24rem] flex-1 resize-none bg-transparent px-3 py-3 font-mono text-[11.5px] leading-[1.6] outline-none"
              style={{ height: `${Math.max(24, lines * 1.6 + 2)}em` }}
              value={text ?? ""}
              onChange={(e) => setText(e.target.value)}
            />
          </div>
          {(msg || errors.length > 0) && (
            <div className="border-t border-line px-4 py-3 text-sm">
              {msg && <p className={errors.length ? "text-bad" : "text-ok"}>{msg}</p>}
              {errors.length > 0 && (
                <ul className="mt-2 space-y-1 font-mono text-xs">
                  {errors.map((e) => (
                    <li key={e.line}>
                      <span className="text-bad">line {e.line}:</span> <span className="text-muted">{e.message}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </Panel>
        <Panel title="Loaded rules">
          <ul>
            {(data?.rules ?? []).map((r) => (
              <li key={r.sid} className="grid grid-cols-[4.5rem_1fr_auto] items-start gap-3 border-t border-line px-4 py-3 first:border-t-0">
                <SevBadge s={r.severity} />
                <span className="min-w-0">
                  <span className="block text-sm">{r.msg}</span>
                  <span className="mt-0.5 block text-xs text-faint">
                    <span className="font-mono">sid {r.sid}</span> · {r.proto}
                    {r.classtype ? ` · ${r.classtype}` : ""}
                    {r.mitre ? ` · ${r.mitre}` : ""}
                  </span>
                </span>
                <span className={`font-mono text-sm ${r.hits ? "text-accent" : "text-faint"}`} title="Packets matched since the rules were loaded">
                  {r.hits.toLocaleString("en-IN")}
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  );
}
