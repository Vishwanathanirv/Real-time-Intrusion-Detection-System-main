import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { Alert, Severity } from "@packeteye/core";

export type AlertStatus = "open" | "acknowledged" | "resolved";
export type StoredAlert = Alert & { status: AlertStatus; note: string | null; source: string };

type Row = Record<string, unknown>;
const fromRow = (r: Row): StoredAlert => ({
  id: r.id as string,
  type: r.type as Alert["type"],
  severity: r.severity as Severity,
  title: r.title as string,
  description: r.description as string,
  src: r.src as string,
  dst: r.dst as string,
  firstSeen: r.first_seen as number,
  lastSeen: r.last_seen as number,
  count: r.count as number,
  mitre: JSON.parse(r.mitre as string),
  evidence: JSON.parse(r.evidence as string),
  status: r.status as AlertStatus,
  note: (r.note as string) ?? null,
  source: r.source as string,
});

export class AlertStore {
  private db: DatabaseSync;
  constructor(file = process.env.DB_FILE ?? "./data/packeteye.db") {
    if (file !== ":memory:") mkdirSync(dirname(file), { recursive: true });
    this.db = new DatabaseSync(file);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        src TEXT NOT NULL,
        dst TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        count INTEGER NOT NULL,
        mitre TEXT NOT NULL,
        evidence TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        note TEXT,
        source TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS alerts_seen ON alerts (last_seen);
      CREATE INDEX IF NOT EXISTS alerts_status ON alerts (status, last_seen);
    `);
  }

  /** Inserts a new alert or updates the running count of a deduplicated one. */
  upsert(a: Alert, source: string): StoredAlert {
    const id = `${source}-${a.id}`;
    this.db
      .prepare(`INSERT INTO alerts (id, type, severity, title, description, src, dst, first_seen, last_seen, count, mitre, evidence, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET severity = excluded.severity, description = excluded.description, last_seen = excluded.last_seen,
          count = excluded.count, evidence = excluded.evidence`)
      .run(id, a.type, a.severity, a.title, a.description, a.src, a.dst, Math.round(a.firstSeen), Math.round(a.lastSeen), a.count, JSON.stringify(a.mitre), JSON.stringify(a.evidence), source);
    return this.get(id)!;
  }

  get(id: string): StoredAlert | null {
    const r = this.db.prepare("SELECT * FROM alerts WHERE id = ?").get(id) as Row | undefined;
    return r ? fromRow(r) : null;
  }

  list(q: { status?: AlertStatus; severity?: Severity; type?: string; limit?: number }): StoredAlert[] {
    const where: string[] = [];
    const args: (string | number)[] = [];
    for (const [col, v] of [["status", q.status], ["severity", q.severity], ["type", q.type]] as const) {
      if (v) {
        where.push(`${col} = ?`);
        args.push(v);
      }
    }
    return (this.db.prepare(`SELECT * FROM alerts ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY last_seen DESC LIMIT ?`).all(...args, Math.min(q.limit ?? 100, 500)) as Row[]).map(fromRow);
  }

  setStatus(id: string, status: AlertStatus, note?: string): StoredAlert | null {
    this.db.prepare("UPDATE alerts SET status = ?, note = COALESCE(?, note) WHERE id = ?").run(status, note ?? null, id);
    return this.get(id);
  }

  summary(since: number) {
    const bySeverity = this.db.prepare("SELECT severity, COUNT(*) AS n FROM alerts WHERE last_seen >= ? GROUP BY severity").all(since) as { severity: Severity; n: number }[];
    const byType = this.db.prepare("SELECT type, COUNT(*) AS n FROM alerts WHERE last_seen >= ? GROUP BY type ORDER BY n DESC").all(since) as { type: string; n: number }[];
    const open = (this.db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE status = 'open'").get() as { n: number }).n;
    return { bySeverity, byType, open };
  }

  close() {
    this.db.close();
  }
}
