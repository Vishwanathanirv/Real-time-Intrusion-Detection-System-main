import { useState } from "react";
import { usePoll, type Alert } from "../lib";
import { AlertDrawer, AlertRow, Panel } from "../ui";

const STATUSES = ["open", "acknowledged", "resolved"] as const;
const SEVERITIES = ["", "critical", "high", "medium", "low"] as const;

export function Alerts() {
  const [status, setStatus] = useState<(typeof STATUSES)[number]>("open");
  const [sev, setSev] = useState<(typeof SEVERITIES)[number]>("");
  const { data, reload } = usePoll<{ alerts: Alert[] }>(`/api/alerts?status=${status}${sev ? `&severity=${sev}` : ""}&limit=200`, 3000);
  const [open, setOpen] = useState<Alert | null>(null);
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Alerts</h1>
        <p className="mt-1 text-sm text-muted">Repeated detections are grouped into one alert with a count, so the queue stays readable during an attack.</p>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <div className="inline-flex rounded-xl border border-line bg-panel p-1" role="tablist">
          {STATUSES.map((s) => (
            <button key={s} role="tab" aria-selected={status === s} onClick={() => setStatus(s)} className={`rounded-lg px-3.5 py-1.5 text-sm capitalize ${status === s ? "bg-panel-2 text-ink" : "text-muted hover:text-ink"}`}>
              {s}
            </button>
          ))}
        </div>
        <select className="field w-auto" value={sev} onChange={(e) => setSev(e.target.value as typeof sev)} aria-label="Severity">
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s ? s[0].toUpperCase() + s.slice(1) : "All severities"}
            </option>
          ))}
        </select>
      </div>
      <Panel>
        {data?.alerts.length ? (
          <ul className="-mt-px">
            {data.alerts.map((a) => (
              <AlertRow key={a.id} a={a} onOpen={setOpen} />
            ))}
          </ul>
        ) : (
          <p className="px-4 py-12 text-center text-sm text-muted">Nothing here.</p>
        )}
      </Panel>
      {open && <AlertDrawer alert={open} onClose={() => setOpen(null)} onChange={() => void reload()} />}
    </div>
  );
}
