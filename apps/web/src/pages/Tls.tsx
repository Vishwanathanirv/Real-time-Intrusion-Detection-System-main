import { usePoll } from "../lib";
import { Kpi, Panel } from "../ui";

export type TlsClient = { ja4: string; hosts: number; hostList: string[]; snis: string[]; connections: number; first: number; last: number; profile: string | null };

/** Splits a JA4 into its readable first part (protocol, version, SNI, counts, ALPN) and the two hashes. */
export function Ja4({ fp }: { fp: string }) {
  const [a, b, c] = fp.split("_");
  return (
    <span className="font-mono text-xs">
      <span className="text-ink">{a}</span>
      <span className="text-faint">_{b}_{c}</span>
    </span>
  );
}

export function decodeJa4(fp: string) {
  const a = fp.split("_")[0];
  const v: Record<string, string> = { "13": "TLS 1.3", "12": "TLS 1.2", "11": "TLS 1.1", "10": "TLS 1.0" };
  const alpn = a.slice(8, 10);
  return `${v[a.slice(1, 3)] ?? a.slice(1, 3)} · ${a[3] === "d" ? "sends a server name" : "no server name"} · ${Number(a.slice(4, 6))} ciphers · ${Number(a.slice(6, 8))} extensions · ${alpn === "00" ? "no ALPN" : `ALPN ${alpn === "h2" ? "h2" : alpn === "h1" ? "http/1.1" : alpn}`}`;
}

export function TlsTable({ clients, common }: { clients: TlsClient[]; common: number }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="label text-left">
            <th className="px-4 py-2 font-medium">Fingerprint (JA4)</th>
            <th className="px-2 py-2 font-medium">Looks like</th>
            <th className="px-2 py-2 text-right font-medium">Hosts</th>
            <th className="px-2 py-2 text-right font-medium">Connections</th>
            <th className="hidden px-4 py-2 font-medium lg:table-cell">Server names</th>
          </tr>
        </thead>
        <tbody>
          {clients.map((c) => {
            const rare = c.hosts < common;
            return (
              <tr key={c.ja4} className="border-t border-line align-top">
                <td className="px-4 py-3">
                  <Ja4 fp={c.ja4} />
                  <div className="mt-1 text-xs text-faint">{decodeJa4(c.ja4)}</div>
                </td>
                <td className="px-2 py-3">
                  {c.profile ?? <span className="text-muted">unknown client</span>}
                  {rare && <span className="ml-2 rounded-sm bg-bad-soft px-1.5 py-0.5 font-mono text-[10.5px] uppercase text-bad">rare</span>}
                </td>
                <td className="px-2 py-3 text-right font-mono" title={c.hostList.join(", ")}>
                  {c.hosts}
                </td>
                <td className="px-2 py-3 text-right font-mono text-muted">{c.connections.toLocaleString("en-IN")}</td>
                <td className="hidden max-w-xs px-4 py-3 font-mono text-xs text-muted lg:table-cell">{c.snis.length ? c.snis.slice(0, 3).join(", ") : "(none sent)"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function Tls() {
  const { data } = usePoll<{ clients: TlsClient[]; commonHosts: number }>("/api/tls", 4000);
  const clients = data?.clients ?? [];
  const rare = clients.filter((c) => c.hosts < (data?.commonHosts ?? 3));
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-[1.7rem] font-bold tracking-tight">TLS clients</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted">
          Encryption hides what a program says, but not how it says hello. Every TLS connection starts with a ClientHello whose cipher suites, extensions and signature algorithms are chosen by the software, not the user. PacketEye turns each one
          into a JA4 fingerprint. Browsers and system services are shared by many machines; a fingerprint used by one machine only is worth a look.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Kpi label="Distinct clients" value={clients.length} />
        <Kpi label="Rare clients" value={rare.length} sub={`used by fewer than ${data?.commonHosts ?? 3} hosts`} tone={rare.length ? "bad" : "ok"} />
        <Kpi label="TLS connections" value={clients.reduce((a, c) => a + c.connections, 0).toLocaleString("en-IN")} />
        <Kpi label="Without ALPN" value={clients.filter((c) => c.ja4.slice(8, 10) === "00").length} sub="browsers always send one" />
      </div>
      <Panel title="Fingerprint inventory, rarest first">{clients.length ? <TlsTable clients={clients} common={data?.commonHosts ?? 3} /> : <p className="px-4 py-12 text-center text-sm text-muted">No TLS handshakes seen yet.</p>}</Panel>
    </div>
  );
}
