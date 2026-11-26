import { useEffect, useRef, type KeyboardEvent as RKeyboardEvent, type PointerEvent as RPointerEvent } from "react";
import { frameAt } from "@packeteye/core";
import { clock, type Alert, type Frame } from "./lib";

/**
 * Rewind: the network as it was at any moment in the last five minutes. The recorder keeps one
 * frame a second (who was talking to whom, and how much), and alerts carry their own first and last
 * seen times, so the map can be redrawn for any second and played forward.
 */
export type Replay = { t: number; playing: boolean; speed: number; alertId?: string };

export const SPEEDS = [1, 4, 16];

/** The alerts as they stood at time `t`: only those already raised, all still open. */
export function alertsAt(alerts: Alert[], t: number): Alert[] {
  return alerts
    .filter((a) => a.firstSeen <= t)
    .map((a) => {
      const span = Math.max(1, a.lastSeen - a.firstSeen);
      const count = a.lastSeen <= t ? a.count : Math.max(1, Math.round((a.count * (t - a.firstSeen)) / span));
      return { ...a, status: "open" as const, note: null, lastSeen: Math.min(a.lastSeen, t), count };
    });
}

/** Where an incident's replay starts and stops: a few seconds of calm before it, and after it ends. */
export function incidentWindow(a: Alert, frames: readonly Frame[]) {
  const first = frames[0]?.t ?? a.firstSeen;
  const last = frames[frames.length - 1]?.t ?? a.lastSeen;
  return { from: Math.max(first, a.firstSeen - 8_000), to: Math.min(last, a.lastSeen + 6_000) };
}

export const canReplay = (a: Alert, frames: readonly Frame[]) => frames.length > 1 && a.lastSeen >= frames[0].t;

export { frameAt };

/** Moves the playhead while playing, and stops at the newest frame. */
export function useReplayClock(replay: Replay | null, end: number, set: (r: Replay | null) => void) {
  const ref = useRef(replay);
  ref.current = replay;
  const playing = replay?.playing ?? false;
  useEffect(() => {
    if (!playing) return;
    let last = performance.now();
    const id = setInterval(() => {
      const r = ref.current;
      if (!r) return;
      const now = performance.now();
      const t = r.t + (now - last) * r.speed;
      last = now;
      set(t >= end ? { ...r, t: end, playing: false } : { ...r, t });
    }, 100);
    return () => clearInterval(id);
  }, [playing, end, set]);
}

/** The recorded window: traffic, a red tick per alert, and a draggable playhead. */
export function Scrubber({ frames, alerts, replay, onChange, onExit }: { frames: readonly Frame[]; alerts: Alert[]; replay: Replay; onChange: (r: Replay) => void; onExit: () => void }) {
  const track = useRef<SVGSVGElement>(null);
  const start = frames[0]?.t ?? replay.t;
  const end = frames[frames.length - 1]?.t ?? replay.t;
  const span = Math.max(1000, end - start);
  const W = 600;
  const H = 56;
  const max = Math.max(10, ...frames.map((f) => f.packets));
  const x = (t: number) => ((t - start) / span) * W;
  const d = frames.map((f, i) => `${i ? "L" : "M"}${x(f.t).toFixed(1)},${(H - 3 - (f.packets / max) * (H - 10)).toFixed(1)}`).join(" ");
  const seek = (t: number) => onChange({ ...replay, t: Math.max(start, Math.min(end, t)) });
  const fromPointer = (e: RPointerEvent) => {
    const r = track.current!.getBoundingClientRect();
    seek(start + ((e.clientX - r.left) / r.width) * span);
  };
  const onKey = (e: RKeyboardEvent) => {
    const step = e.shiftKey ? 10_000 : 1_000;
    if (e.key === "ArrowLeft") seek(replay.t - step);
    else if (e.key === "ArrowRight") seek(replay.t + step);
    else if (e.key === "Home") seek(start);
    else if (e.key === "End") seek(end);
    else return;
    e.preventDefault();
  };
  const behind = Math.round((end - replay.t) / 1000);
  const ticks = alerts.filter((a) => a.firstSeen >= start && a.firstSeen <= end);
  return (
    <div className="flex w-full flex-wrap items-center gap-x-3 gap-y-2" aria-label="Rewind controls" role="group">
      <div className="flex items-center gap-1.5">
        <span className="tape-badge">REWIND</span>
        <button className="btn h-9 w-9 justify-center px-0" onClick={() => seek(replay.t - 10_000)} aria-label="Back ten seconds" title="Back 10 s (Shift+←)">
          <svg viewBox="0 0 24 24" className="h-4 w-4" fill="currentColor" aria-hidden>
            <path d="M11 6v12L3 12zM20 6v12l-8-6z" />
          </svg>
        </button>
        <button
          className="btn btn-warn h-9 w-9 justify-center px-0"
          onClick={() => onChange({ ...replay, playing: !replay.playing, t: !replay.playing && replay.t >= end ? start : replay.t })}
          aria-label={replay.playing ? "Pause the replay" : "Play the replay"}
          title="Play or pause (Space)"
        >
          <svg viewBox="0 0 24 24" className="h-4 w-4" fill="currentColor" aria-hidden>
            <path d={replay.playing ? "M6 5h4v14H6zM14 5h4v14h-4z" : "M7 4l13 8-13 8z"} />
          </svg>
        </button>
        <button
          className="btn lcd h-9 w-12 justify-center px-0 text-xs"
          onClick={() => onChange({ ...replay, speed: SPEEDS[(SPEEDS.indexOf(replay.speed) + 1) % SPEEDS.length] })}
          aria-label={`Playback speed ${replay.speed} times. Change speed`}
        >
          {replay.speed}×
        </button>
      </div>
      <svg
        ref={track}
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        className="tape min-w-0 flex-1 basis-56 cursor-ew-resize touch-none"
        style={{ height: H }}
        role="slider"
        tabIndex={0}
        aria-label="Replay position"
        aria-valuemin={0}
        aria-valuemax={Math.round(span / 1000)}
        aria-valuenow={Math.round((replay.t - start) / 1000)}
        aria-valuetext={`${behind} seconds before now, ${clock(replay.t)}`}
        onKeyDown={onKey}
        onPointerDown={(e) => {
          (e.target as Element).setPointerCapture?.(e.pointerId);
          onChange({ ...replay, playing: false });
          fromPointer(e);
        }}
        onPointerMove={(e) => e.buttons && fromPointer(e)}
      >
        {frames.length > 1 && <path d={`${d} L${W},${H} L0,${H} Z`} fill="var(--warn)" fillOpacity={0.14} />}
        <path d={d} fill="none" stroke="var(--warn)" strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
        {ticks.map((a) => (
          <line key={a.id} x1={x(a.firstSeen)} x2={x(a.firstSeen)} y1={0} y2={H} stroke="var(--bad)" strokeWidth={2} vectorEffect="non-scaling-stroke" />
        ))}
        <rect x={0} y={0} width={Math.max(0, x(replay.t))} height={H} fill="var(--warn)" fillOpacity={0.06} />
        <line x1={x(replay.t)} x2={x(replay.t)} y1={0} y2={H} stroke="var(--ink)" strokeWidth={2} vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="flex items-center gap-2">
        <span className="lcd text-[12px] leading-tight">
          <span className="block text-warn">
            T−{Math.floor(behind / 60)}:{String(behind % 60).padStart(2, "0")}
          </span>
          <span className="block text-faint">{clock(replay.t)}</span>
        </span>
        <button className="btn h-9" onClick={onExit} title="Back to live (L)">
          Back to live
        </button>
      </div>
    </div>
  );
}
