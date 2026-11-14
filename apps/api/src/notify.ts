import type { Alert } from "@packeteye/core";

/**
 * Optional Telegram notifications for high and critical alerts.
 * Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to enable. At most one message per alert type per minute.
 */
export class TelegramNotifier {
  private last = new Map<string, number>();
  constructor(private token = process.env.TELEGRAM_BOT_TOKEN, private chatId = process.env.TELEGRAM_CHAT_ID, private fetchFn: typeof fetch = fetch) {}

  get enabled() {
    return Boolean(this.token && this.chatId);
  }

  format(a: Alert): string {
    const icon = a.severity === "critical" ? "🛑" : "⚠️";
    return `${icon} *${a.severity.toUpperCase()}*: ${a.title}\n${a.description}\nMITRE ${a.mitre.id} (${a.mitre.tactic})\n${a.src} → ${a.dst}`;
  }

  async send(a: Alert, now = Date.now()): Promise<boolean> {
    if (!this.enabled || (a.severity !== "high" && a.severity !== "critical")) return false;
    if (now - (this.last.get(a.type) ?? -Infinity) < 60_000) return false;
    this.last.set(a.type, now);
    try {
      const res = await this.fetchFn(`https://api.telegram.org/bot${this.token}/sendMessage`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ chat_id: this.chatId, text: this.format(a), parse_mode: "Markdown" }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}
