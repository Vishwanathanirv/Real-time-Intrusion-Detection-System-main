import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";

/** First-visit briefing: whether this visitor has already seen it, kept in this browser only. */
export function useBriefing(): [boolean, (show: boolean) => void] {
  const [show, setShow] = useState(() => {
    try {
      return localStorage.getItem("packeteye-briefed") !== "1";
    } catch {
      return true;
    }
  });
  const set = (v: boolean) => {
    setShow(v);
    if (!v)
      try {
        localStorage.setItem("packeteye-briefed", "1");
      } catch {
        /* private mode */
      }
  };
  return [show, set];
}

/**
 * The idea, on the first screen: the problem, the one idea, and why it's different. It sits over
 * the live scope, which keeps sweeping behind it, so the pitch and the proof arrive together.
 */
export function Briefing({ onWatch, onExplain, onClose }: { onWatch: () => void; onExplain: () => void; onClose: () => void }) {
  const first = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    first.current?.focus({ preventScroll: true });
  }, []);
  return (
    <section className="briefing" aria-labelledby="briefing-title">
      <div className="briefing-inner">
        <p className="briefing-eyebrow lcd">PACKETEYE · SONAR FOR YOUR NETWORK</p>
        <h1 id="briefing-title" className="briefing-title">
          See attacks the way radar sees <span className="text-accent">aircraft.</span>
        </h1>
        <dl className="briefing-points">
          <div>
            <dt>The problem</dt>
            <dd>Intrusion detection buries people in log lines. The one row that matters hides among thousands, and only experts can read it.</dd>
          </div>
          <div>
            <dt>The idea</dt>
            <dd>Draw the network as a live sonar scope. Every computer is a contact, every conversation a line, and an attack lights up coral the moment its shape appears. No message is ever read.</dd>
          </div>
          <div>
            <dt>Why it's different</dt>
            <dd>Behaviour, signatures and machine learning in one sensor that runs right here in your browser. Every alert can be replayed, tested against a patient attacker, explained in plain words and shared as a link.</dd>
          </div>
        </dl>
        <div className="mt-6 flex flex-wrap gap-2">
          <button ref={first} className="btn btn-accent h-11 px-5 text-[0.95rem]" onClick={onWatch}>
            Watch an attack get caught →
          </button>
          <Link to="/how" className="btn h-11 px-4 text-[0.95rem]" onClick={onClose}>
            How it works
          </Link>
          <button className="btn h-11 px-4 text-[0.95rem]" onClick={onExplain}>
            I'm new to this
          </button>
        </div>
        <button className="briefing-skip" onClick={onClose}>
          Skip to the live scope <kbd>Esc</kbd>
        </button>
      </div>
    </section>
  );
}
