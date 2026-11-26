import { useCallback, useEffect, useRef, useState } from "react";
import type { Severity } from "./lib";

/** Pitch by severity, so a critical alert is recognisable without looking at the screen. */
export const CHIME_HZ: Record<Severity, number> = { low: 392, medium: 523, high: 784, critical: 1047 };

/**
 * An audible chime whenever a new alert fires, for someone watching with the tab in the
 * background. Off by default; the choice is remembered in this browser. Each chime is counted on
 * <html data-chimes> so it can be tested.
 */
export function useAlertSound(): { on: boolean; toggle: () => void; chime: (s: Severity) => void } {
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
  const chime = useCallback(
    (s: Severity) => {
      if (!on) return;
      const ac = (ctx.current ??= new AudioContext());
      if (ac.state === "suspended") void ac.resume();
      const t = ac.currentTime + 0.01;
      const o = ac.createOscillator();
      const g = ac.createGain();
      o.type = "sine";
      o.frequency.setValueAtTime(CHIME_HZ[s], t);
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(0.18, t + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.35);
      o.connect(g).connect(ac.destination);
      o.start(t);
      o.stop(t + 0.4);
      const el = document.documentElement;
      el.dataset.chimes = String(Number(el.dataset.chimes ?? 0) + 1);
    },
    [on],
  );
  const toggle = useCallback(() => {
    setOn((v) => {
      if (!v) (ctx.current ??= new AudioContext()).resume().catch(() => {});
      return !v;
    });
  }, []);
  return { on, toggle, chime };
}
