import { usePoll } from "../lib";
import { Kpi, Panel } from "../ui";

type Evaluation = {
  generatedAt: string;
  minutes: number;
  packets: number;
  attacks: number;
  perAttack: Record<string, { injected: number; detected: number; meanTimeToDetectMs: number | null }>;
  falseAlertsPerHour: number;
  throughputPps: number;
  avgMicrosPerPacket: number;
};

const LABELS: Record<string, { name: string; mitre: string; how: string }> = {
  port_scan: { name: "Port scan", mitre: "T1046", how: "Distinct destination ports probed by one source on one host in a sliding window." },
  host_sweep: { name: "Host sweep", mitre: "T1018", how: "Distinct hosts contacted on the same port by one source." },
  syn_flood: { name: "SYN flood / DDoS", mitre: "T1498.001", how: "SYN rate per target plus the share of handshakes that never complete; counts spoofed sources." },
  brute_force: { name: "SSH / RDP brute force", mitre: "T1110.001", how: "Short-lived connections to login services from one source, per target." },
  dns_tunnel: { name: "DNS tunnelling", mitre: "T1071.004", how: "Query volume per domain, uniqueness, Shannon entropy and length of subdomains." },
  beaconing: { name: "C2 beaconing", mitre: "T1071.001", how: "Regular connection intervals to one external endpoint (low coefficient of variation)." },
  exfiltration: { name: "Data exfiltration", mitre: "TA0010", how: "Isolation forest trained only on normal flows flags flows that look unlike anything seen before." },
};

export function Detection() {
  const { data, error } = usePoll<Evaluation>("/api/evaluation", 0);
  const totals = data ? Object.values(data.perAttack).reduce((a, v) => ({ i: a.i + v.injected, d: a.d + v.detected }), { i: 0, d: 0 }) : null;
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Detection coverage</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted">
          Measured, not claimed. A labelled replay of office traffic with scheduled attacks runs through the sensor, and each detector is scored on whether and how fast it fired, and on false alerts during clean traffic.
        </p>
      </div>
      {error && <p className="text-sm text-muted">{error}</p>}
      {data && totals && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Kpi label="Attacks detected" value={`${totals.d}/${totals.i}`} sub={`${data.minutes} min replay, ${data.packets.toLocaleString("en-IN")} packets`} tone="ok" />
            <Kpi label="False alerts" value={`${data.falseAlertsPerHour}/hour`} sub="on clean background traffic" />
            <Kpi label="Throughput" value={`${(data.throughputPps / 1000).toFixed(0)}k pkt/s`} sub="single core, Node.js" tone="accent" />
            <Kpi label="Per packet" value={`${data.avgMicrosPerPacket} µs`} sub="decode, flow tracking, all detectors" />
          </div>
          <Panel title="Per technique">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="label text-left">
                    <th className="px-4 py-2 font-medium">Attack</th>
                    <th className="px-2 py-2 font-medium">ATT&amp;CK</th>
                    <th className="hidden px-2 py-2 font-medium md:table-cell">How it is detected</th>
                    <th className="px-2 py-2 text-right font-medium">Detected</th>
                    <th className="px-4 py-2 text-right font-medium">Time to detect</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(data.perAttack).map(([k, v]) => (
                    <tr key={k} className="border-t border-line align-top">
                      <td className="px-4 py-3 font-medium">{LABELS[k]?.name ?? k}</td>
                      <td className="px-2 py-3 font-mono text-xs text-accent">{LABELS[k]?.mitre}</td>
                      <td className="hidden max-w-md px-2 py-3 text-muted md:table-cell">{LABELS[k]?.how}</td>
                      <td className="px-2 py-3 text-right font-mono" style={{ color: v.detected === v.injected ? "var(--ok)" : "var(--warn)" }}>
                        {v.detected}/{v.injected}
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-muted">{v.meanTimeToDetectMs === null ? "–" : `${(v.meanTimeToDetectMs / 1000).toFixed(1)} s`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="px-4 pb-4 pt-1 text-xs leading-relaxed text-faint">
              Flow-based detectors (beaconing, exfiltration) fire when a connection or pattern completes, so they take longer than packet-based ones. Report generated {new Date(data.generatedAt).toLocaleString("en-IN")}; reproduce it with <code className="font-mono">npm run evaluate</code>.
            </p>
          </Panel>
        </>
      )}
    </div>
  );
}
