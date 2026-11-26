import { useEffect, useMemo, useRef, useState } from "react";

export type Command = { id: string; group: string; label: string; keys?: string; run: () => void };

/**
 * The command menu: every action in PacketEye, by name. Ctrl+K, ⌘K or / opens it; type to
 * filter, arrows to move, Enter to run.
 */
export function Palette({ commands, onClose }: { commands: Command[]; onClose: () => void }) {
  const [q, setQ] = useState("");
  const [i, setI] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const shown = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    return commands.filter((c) => words.every((w) => `${c.group} ${c.label}`.toLowerCase().includes(w)));
  }, [q, commands]);
  useEffect(() => input.current?.focus(), []);
  useEffect(() => setI(0), [q]);
  useEffect(() => {
    list.current?.querySelector(`[data-i="${i}"]`)?.scrollIntoView({ block: "nearest" });
  }, [i]);
  const run = (c: Command | undefined) => {
    if (!c) return;
    onClose();
    c.run();
  };
  let group = "";
  return (
    <div className="palette-wrap" onPointerDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Command menu">
        <div className="palette-input">
          <span className="lcd text-accent" aria-hidden>
            ▸
          </span>
          <input
            ref={input}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Type a command: launch, rewind, explain…"
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={shown[i] ? `cmd-${shown[i].id}` : undefined}
            aria-label="Command"
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") setI((x) => Math.min(shown.length - 1, x + 1));
              else if (e.key === "ArrowUp") setI((x) => Math.max(0, x - 1));
              else if (e.key === "Enter") run(shown[i]);
              else if (e.key === "Escape") onClose();
              else return;
              e.preventDefault();
              e.stopPropagation();
            }}
          />
          <kbd>Esc</kbd>
        </div>
        <ul id="palette-list" ref={list} role="listbox" aria-label="Commands" className="palette-list scroll-y">
          {shown.map((c, n) => {
            const head = c.group !== group ? (group = c.group) : null;
            return (
              <li key={c.id} role="presentation">
                {head && <div className="palette-group">{head}</div>}
                <div id={`cmd-${c.id}`} data-i={n} role="option" aria-selected={n === i} className="palette-item" onPointerMove={() => setI(n)} onClick={() => run(c)}>
                  <span>{c.label}</span>
                  {c.keys && <kbd>{c.keys}</kbd>}
                </div>
              </li>
            );
          })}
          {!shown.length && <li className="px-4 py-6 text-center text-sm text-muted">No command matches “{q}”.</li>}
        </ul>
      </div>
    </div>
  );
}
