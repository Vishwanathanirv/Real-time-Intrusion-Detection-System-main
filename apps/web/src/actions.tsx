import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import type { Alert } from "./lib";

/** What any alert view can ask the shell to do, without threading callbacks through every page. */
export type Actions = {
  replay?: (a: Alert) => void;
  canReplay?: (a: Alert) => boolean;
  share?: (a: Alert) => void;
  /** "Explain like I'm new": plain-language notes next to everything technical. */
  plain: boolean;
  setPlain?: (on: boolean) => void;
};

export const ActionsContext = createContext<Actions>({ plain: false });
export const useActions = () => useContext(ActionsContext);

/** The plain-words setting is a per-visitor preference, kept in this browser only. */
export function usePlainSetting(): [boolean, (on: boolean) => void] {
  const [on, setOn] = useState(() => {
    try {
      return new URLSearchParams(location.search).has("explain") || localStorage.getItem("packeteye-plain") === "1";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem("packeteye-plain", on ? "1" : "0");
    } catch {
      /* private mode: the setting just isn't remembered */
    }
  }, [on]);
  return [on, setOn];
}

/** A note in plain words, shown only in "explain like I'm new" mode. */
export function Plain({ children, className = "" }: { children: ReactNode; className?: string }) {
  const { plain } = useActions();
  if (!plain) return null;
  return (
    <p className={`plain ${className}`}>
      <span className="plain-mark" aria-hidden>
        ?
      </span>
      <span>{children}</span>
    </p>
  );
}

/** What each kind of alert means, for someone who has never seen one. */
export const PLAIN: Record<string, { what: string; why: string }> = {
  port_scan: { what: "Someone is trying every door handle on one building. Each door is a port: a numbered entrance to a service, like 22 for remote logins or 443 for websites.", why: "Scanning is how attackers find a way in. It comes before the break-in." },
  host_sweep: { what: "Someone is knocking on every house in the street to see who is home. They are making a list of which computers exist.", why: "It means a machine is mapping the network, often after it has been taken over." },
  syn_flood: { what: "Thousands of callers ring the shop and hang up before saying anything, so real customers can't get through. Each unanswered hello (a SYN) keeps a line busy.", why: "The website or service can slow down or stop for everyone." },
  brute_force: { what: "Someone is at the login screen typing password after password, dozens of times a minute.", why: "One weak password and they are in." },
  dns_tunnel: { what: "DNS is the network's phone book. This computer is looking up 'names' that are really scrambled data, smuggling information out inside the questions.", why: "Firewalls usually let phone-book lookups through, so this is a quiet way to steal data." },
  beaconing: { what: "A computer is calling the same outside number at regular intervals, like clockwork, to check in.", why: "Malware does exactly this to ask the person controlling it for orders." },
  tls_fingerprint: { what: "Every app introduces itself slightly differently when it opens an encrypted connection. This introduction has not been seen from the other computers here.", why: "Unfamiliar software calling the internet is often malware, even when everything it sends is encrypted." },
  anomaly: { what: "The model learned what normal conversations here look like, without ever being shown an attack. This one is unlike all of them, for example a huge upload to an unknown place.", why: "It catches things nobody wrote a rule for, so a person should take a look." },
  rule: { what: "A hand-written rule matched, like an item on a security guard's checklist: 'stop anyone carrying this'.", why: "Someone decided this pattern is worth knowing about every time it happens." },
};
