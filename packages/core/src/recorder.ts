import type { TrafficStats } from "./sensor";

/** One second of the scope: traffic rate and who was talking to whom. */
export type Frame = { t: number; packets: number; bytes: number; graph: TrafficStats["graph"] };

/** Builds the frame for second `t` from the sensor's stats (the last complete second of the series). */
export function frameOf(stats: Pick<TrafficStats, "series" | "graph">, t: number, maxEdges = 60): Frame {
  const done = stats.series.length > 1 ? stats.series[stats.series.length - 2] : stats.series[0];
  const edges = stats.graph.edges.slice(0, maxEdges);
  const keep = new Set(edges.flatMap((e) => [e.src, e.dst]));
  return { t, packets: done?.packets ?? 0, bytes: done?.bytes ?? 0, graph: { nodes: stats.graph.nodes.filter((n) => keep.has(n.ip)), edges } };
}

/**
 * The flight recorder: keeps the last few minutes of frames so an incident can be replayed on the
 * scope. Memory is bounded by the window (one frame a second).
 */
export class FlightRecorder {
  private list: Frame[] = [];
  constructor(private keepMs = 5 * 60_000) {}

  record(frame: Frame): void {
    const last = this.list[this.list.length - 1];
    if (last && frame.t <= last.t) return;
    this.list.push(frame);
    const cut = frame.t - this.keepMs;
    let drop = 0;
    while (drop < this.list.length && this.list[drop].t < cut) drop++;
    if (drop) this.list.splice(0, drop);
  }

  get frames(): readonly Frame[] {
    return this.list;
  }
}

/** The frame showing the scope at time `t`: the latest one recorded at or before it (or the first). */
export function frameAt(frames: readonly Frame[], t: number): Frame | undefined {
  if (!frames.length) return undefined;
  let lo = 0;
  let hi = frames.length - 1;
  if (t < frames[0].t) return frames[0];
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (frames[mid].t <= t) lo = mid;
    else hi = mid - 1;
  }
  return frames[lo];
}
