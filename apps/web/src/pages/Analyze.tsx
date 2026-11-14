import { useState } from "react";
import { bytes, DEMO, num, type Alert } from "../lib";
import { AlertDrawer, AlertRow, Bars, Kpi, Panel } from "../ui";

type Result = {
  file: string;
  packets: number;
  skipped: number;
  durationSec: number;
  flows: number;
  bytes: number;
  protocols: Record<string, number>;
  topTalkers: { ip: string; bytes: number; packets: number }[];
  topPorts: { port: number; packets: number }[];
  alerts: Alert[];
};

export function Analyze() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [open, setOpen] = useState<Alert | null>(null);
  const [drag, setDrag] = useState(false);

  async function upload(file: File) {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      if (DEMO) {
        const { demo } = await import("../demo/server");
        setResult(await demo.analyze(file));
        return;
      }
      const fd = new FormData();
      fd.append("file", file);
      const res = await fetch("/api/pcap", { method: "POST", body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Upload failed");
      setResult(data);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function sampleBlob() {
    if (DEMO) return (await import("../demo/server")).demo.samplePcap();
    return (await fetch("/api/pcap/sample")).blob();
  }

  async function trySample() {
    await upload(new File([await sampleBlob()], "packeteye-sample.pcap"));
  }

  async function downloadSample() {
    const url = URL.createObjectURL(await sampleBlob());
    const a = document.createElement("a");
    a.href = url;
    a.download = "packeteye-sample.pcap";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-[1.7rem] font-bold tracking-tight">Analyse a capture</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted">Upload a .pcap from Wireshark or tcpdump (up to 50 MB). {DEMO ? "It is analysed right here in your browser by the same detectors; the file never leaves your machine." : "It runs through the same detectors in an isolated sensor and nothing is stored."}</p>
      </div>
      <label
        onDragOver={(e) => {
          e.preventDefault();
          setDrag(true);
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDrag(false);
          if (e.dataTransfer.files[0]) void upload(e.dataTransfer.files[0]);
        }}
        className={`panel flex cursor-pointer flex-col items-center justify-center gap-2 border-dashed px-6 py-12 text-center transition ${drag ? "border-accent" : ""}`}
      >
        <input type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" className="hidden" onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])} />
        <span className="text-base font-medium">{busy ? "Analysing…" : "Drop a .pcap here or click to choose"}</span>
        <span className="text-xs text-faint">Ethernet, VLAN, raw IP and Linux cooked captures · IPv4 · pcap (convert pcapng with editcap -F pcap)</span>
      </label>
      <div className="flex flex-wrap gap-2">
        <button className="btn" onClick={trySample} disabled={busy}>
          Analyse the sample capture
        </button>
        <button className="btn" onClick={downloadSample} disabled={busy}>
          Download sample .pcap
        </button>
      </div>
      {error && <p className="rounded-sm bg-bad-soft px-3 py-2 text-sm text-bad">{error}</p>}
      {result && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
            <Kpi label="Packets" value={num(result.packets)} sub={result.skipped ? `${num(result.skipped)} non-IPv4 skipped` : result.file} />
            <Kpi label="Duration" value={`${result.durationSec}s`} />
            <Kpi label="Flows" value={num(result.flows)} />
            <Kpi label="Data" value={bytes(result.bytes)} />
            <Kpi label="Alerts" value={result.alerts.length} tone={result.alerts.length ? "bad" : "ok"} sub={`${new Set(result.alerts.map((a) => a.mitre.id)).size} ATT&CK techniques`} />
          </div>
          <div className="grid gap-5 lg:grid-cols-[1.6fr_1fr]">
            <Panel title="Findings">
              {result.alerts.length ? (
                <ul className="-mt-px">
                  {result.alerts.map((a) => (
                    <AlertRow key={a.id} a={a} onOpen={setOpen} absolute />
                  ))}
                </ul>
              ) : (
                <p className="px-4 py-10 text-center text-sm text-muted">No threats found in this capture.</p>
              )}
            </Panel>
            <Panel title="Top talkers">
              <div className="p-4">
                <Bars rows={result.topTalkers.slice(0, 8).map((t) => ({ label: t.ip, value: t.bytes, hint: bytes(t.bytes) }))} />
              </div>
            </Panel>
          </div>
        </>
      )}
      {open && <AlertDrawer alert={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
