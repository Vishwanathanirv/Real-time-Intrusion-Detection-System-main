import { Plain } from "../actions";
import { useState } from "react";
import { usePoll, type Alert } from "../lib";
import { AlertRow } from "../ui";

const STATUSES = ["open", "acknowledged", "resolved"] as const;
const SEVERITIES = ["", "critical", "high", "medium", "low"] as const;

/** Every alert, filterable by status and severity. Opening one selects it on the overview. */
export function Alerts({ onOpen }: { onOpen: (a: Alert) => void }) {
  const [status, setStatus] = useState<(typeof STATUSES)[number]>("open");
  const [sev, setSev] = useState<(typeof SEVERITIES)[number]>("");
  const { data } = usePoll<{ alerts: Alert[] }>(`/api/alerts?status=${status}${sev ? `&severity=${sev}` : ""}&limit=200`, 3000);
  return (
    <div className="space-y-5">
      <div>
        <h1 className="display text-[1.6rem] font-bold leading-tight">Alerts</h1>
        <p className="mt-2 text-[0.95rem] text-muted">Repeats fold into one row with a count, so the list stays readable during an attack. Open an alert to see it on the network map.</p>
        <Plain className="mt-3 max-w-2xl">Open alerts need someone to look at them; acknowledged means someone is on it; resolved means it is dealt with.</Plain>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <div className="inline-flex rounded-md border border-line bg-surface p-1" role="tablist">
          {STATUSES.map((s) => (
            <button key={s} role="tab" aria-selected={status === s} onClick={() => setStatus(s)} className={`rounded-sm px-3.5 py-1.5 text-sm capitalize ${status === s ? "bg-panel-2 text-ink" : "text-muted hover:text-ink"}`}>
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
      {data?.alerts.length ? (
        <ul className="alert-list panel overflow-hidden" aria-label={`${status} alerts`}>
          {data.alerts.map((a) => (
            <AlertRow key={a.id} a={a} onOpen={onOpen} />
          ))}
        </ul>
      ) : (
        data ? <p className="panel px-4 py-12 text-center text-sm text-muted">{`No ${status} alerts.`}</p> : <div className="skeleton h-40" aria-label="Loading" />
      )}
    </div>
  );
}
