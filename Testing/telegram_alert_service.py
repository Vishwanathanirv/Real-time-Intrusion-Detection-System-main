
"""
Telegram alert service that polls MySQL for new anomaly rows and only
sends Telegram notifications for attack types present in ALERT_WHITELIST.

- Edit ALERT_WHITELIST to include the attack names you want alerts for.
- last_id is persisted to last_id.txt so restarts don't resend old alerts.
"""

import mysql.connector
import time
import requests
import datetime
from pathlib import Path


import os
from dotenv import load_dotenv

# Load environment variables from the root .env file
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

DB_CONFIG = dict(
    host=os.getenv("DB_HOST", "localhost"),
    user=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASSWORD", ""),
    database=os.getenv("DB_NAME", "packeteye"),
)


ALERT_WHITELIST = [
    "DDOS",
    "PortScan",
    "DoS Hulk",
    "DOS"
    
]

POLL_INTERVAL = 5 
LAST_ID_FILE = Path("last_id.txt")



whitelist_lower = {a.lower() for a in ALERT_WHITELIST}

def load_last_id() -> int:
    if LAST_ID_FILE.exists():
        try:
            return int(LAST_ID_FILE.read_text().strip() or 0)
        except Exception:
            return 0
    return 0

def save_last_id(last_id: int):
    try:
        LAST_ID_FILE.write_text(str(int(last_id)))
    except Exception as e:
        print("⚠️ Failed to persist last_id:", e)

def send_telegram_alert(packet: dict):
    """Send alert message to Telegram (formatted)."""
    msg = (
        f"🚨 *Anomaly Detected!* \n"
        f"🆔 ID: `{packet.get('id')}`\n"
        f"🕒 `{packet.get('timestamp')}`\n"
        f"📡 *Source:* `{packet.get('src_ip')}`\n"
        f"🎯 *Destination:* `{packet.get('dest_ip')}`\n"
        f"📘 *Protocol:* `{packet.get('protocol')}`\n"
        f"📏 *Length:* `{packet.get('length')}` bytes\n"
        f"⚠️ *Reason:* {packet.get('reason')}\n"
        f"💥 *Attack Type:* *{packet.get('attack_type') or 'Unknown'}*"
    )
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            data={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"},
            timeout=5
        )
        if resp.ok:
            print(f"✅ Sent Telegram alert for ID {packet.get('id')}")
        else:
            print(f"⚠️ Telegram API error {resp.status_code}: {resp.text}")
    except Exception as e:
        print("⚠️ Telegram send failed:", e)

def connect_db():
    """Create a new DB connection and return (conn, cursor)."""
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    return conn, cursor

def main():
    print("📡 Telegram Alert Service (whitelist) starting...")
    last_id = load_last_id()
    print("▶️ Starting from last_id =", last_id)

    conn, cursor = connect_db()

    while True:
        try:
            
            cursor.execute(
                "SELECT * FROM packets WHERE id > %s AND status = 'Anomaly' ORDER BY id ASC",
                (last_id,)
            )
            rows = cursor.fetchall()

            for packet in rows:
                
                atype = (packet.get("attack_type") or "").strip()
                atype_lower = atype.lower()

                
                if atype_lower in whitelist_lower:
                    send_telegram_alert(packet)
                else:
                    print(f"ℹ️ Skipped ID {packet.get('id')} (attack_type='{atype}')")

                
                last_id = max(last_id, packet.get("id", last_id))

            if rows:
                save_last_id(last_id)
                conn.commit()

            time.sleep(POLL_INTERVAL)

        except mysql.connector.errors.OperationalError as e:
       
            print("🔄 Lost DB connection. Reconnecting in 5s...", e)
            time.sleep(5)
            try:
                conn.close()
            except Exception:
                pass
            conn, cursor = connect_db()

        except Exception as e:
            print("❌ Error in main loop:", e)
            time.sleep(5)

if __name__ == "__main__":
    main()
