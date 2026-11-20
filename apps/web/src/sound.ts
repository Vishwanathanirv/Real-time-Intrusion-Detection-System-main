import { useCallback, useEffect, useRef, useState } from "react";
import type { Severity } from "./lib";

/** A sonar ping's pitch by severity: the worse the alert, the higher the ping. */
export const PING_HZ: Record<Severity, number> = { low: 392, medium: 523, high: 784, critical: 1047 };

/**
 * Sonar pings: an audible ping, with a faint echo, whenever a new alert fires. Off by default; the
 * choice is remembered in this browser. Each ping is counted on <html data-pings> so it can be tested.
 */
export function useSonar(): { on: boolean; toggle: () => void; ping: (s: Severity) => void } {
  const [on, setOn] = useState(() => {
    try {
      return localStorage.getItem("packeteye-sound") === "1";
    } catch {
      return false;
    }
  });
  const ctx = useRef<AudioContext | null>(null);
  useEffect(() => {
    try {
      localStorage.setItem("packeteye-sound", on ? "1" : "0");
    } catch {
      /* private mode */
    }
  }, [on]);
  const ping = useCallback(
    (s: Severity) => {
      if (!on) return;
      const ac = (ctx.current ??= new AudioContext());
      if (ac.state === "suspended") void ac.resume();
      const t = ac.currentTime + 0.01;
      for (const [delay, gain] of [
        [0, 0.22],
        [0.32, 0.06],
      ]) {
        const o = ac.createOscillator();
        const g = ac.createGain();
        o.type = "sine";
        o.frequency.setValueAtTime(PING_HZ[s], t + delay);
        o.frequency.exponentialRampToValueAtTime(PING_HZ[s] * 0.94, t + delay + 0.9);
        g.gain.setValueAtTime(0.0001, t + delay);
        g.gain.exponentialRampToValueAtTime(gain, t + delay + 0.015);
        g.gain.exponentialRampToValueAtTime(0.0001, t + delay + 0.9);
        o.connect(g).connect(ac.destination);
        o.start(t + delay);
        o.stop(t + delay + 1);
      }
      const el = document.documentElement;
      el.dataset.pings = String(Number(el.dataset.pings ?? 0) + 1);
    },
    [on],
  );
  const toggle = useCallback(() => {
    setOn((v) => {
      if (!v) (ctx.current ??= new AudioContext()).resume().catch(() => {});
      return !v;
    });
  }, []);
  return { on, toggle, ping };
}
