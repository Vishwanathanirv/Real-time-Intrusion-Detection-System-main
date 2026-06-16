import pandas as pd
import numpy as np
import joblib
import mysql.connector
import datetime
import time
import random
import requests
from pathlib import Path


CSV_PATH = Path(r"F:\packeteye-pro\datasets\payload_data_CICIDS2017_17features.csv")
CHUNK_SIZE = 5000
DETECTIONS_LOG_CSV = Path("detections_log.csv")


SIMULATE_TIMING = True
MIN_DELAY = 0.001
MAX_DELAY = 0.02
BURST_PROB = 0.01
BURST_SIZE = 25
BURST_DELAY = 0.0005


AMPLIFY_ATTACKS = True
AMPLIFY_LABEL = "DDoS"
AMPLIFY_FACTOR = 5

ISO_MODEL = "mlmodel/anomaly_model.pkl"
ISO_SCALER = "mlmodel/scaler.pkl"
CLF_MODEL = "mlmodel/attack_classifier.pkl"
CLF_SCALER = "mlmodel/scaler.pkl" # Shared scaler
ATTACK_LABELS = "mlmodel/attack_labels.pkl"


import os
from dotenv import load_dotenv

# Load environment variables from root
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")
ALERT_ATTACKS = ["DDoS", "PortScan", "Botnet", "Infiltration"]

def send_telegram_alert(src_ip, dest_ip, attack_type, reason):
    """Send alert to Telegram when a specific attack is detected."""
    try:
        message = (
            f"🚨 *CHANAKYA SHIELD ALERT!*\n\n"
            f"🕒 *Time:* {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"💀 *Attack Type:* {attack_type}\n"
            f"📡 *Source IP:* {src_ip}\n"
            f"🎯 *Destination IP:* {dest_ip}\n"
            f"⚠️ *Reason:* {reason}"
        )
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        data = {"chat_id": CHAT_ID, "text": message, "parse_mode": "Markdown"}
        res = requests.post(url, data=data, timeout=5)
        if res.status_code == 200:
            print(f"📲 Telegram alert sent: {attack_type} ({src_ip} → {dest_ip})")
        else:
            print(f"⚠️ Telegram alert failed [{res.status_code}]: {res.text}")
    except Exception as e:
        print("⚠️ Telegram alert error:", e)


DB_CONFIG = dict(
    host=os.getenv("DB_HOST", "localhost"),
    user=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASSWORD", ""),
    database=os.getenv("DB_NAME", "packeteye")
)
conn = mysql.connector.connect(**DB_CONFIG)
cursor = conn.cursor()


print("🔹 Loading models...")
iso_model = joblib.load(ISO_MODEL)
iso_scaler = joblib.load(ISO_SCALER)

try:
    clf_model = joblib.load(CLF_MODEL)
    clf_scaler = joblib.load(CLF_SCALER)
    label_map = joblib.load(ATTACK_LABELS)
    # Invert map to get Index -> Label
    attack_labels = {v: k for k, v in label_map.items()}
    have_classifier = True
    print("✅ Attack classifier loaded.")
except:
    have_classifier = False
    attack_labels = ["DDoS", "PortScan", "Botnet", "Infiltration", "WebAttack", "BruteForce"]
    print("⚠️ No classifier found — using random attack type simulation.")

# Features must match train_model.py EXACTLY
selected_features = [
    'Destination Port','Flow Duration','Total Fwd Packets','Total Backward Packets',
    'Total Length of Fwd Packets','Total Length of Bwd Packets',
    'Fwd Packet Length Mean','Bwd Packet Length Mean','Flow Packets/s',
    'FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count',
    'ACK Flag Count','URG Flag Count','CWE Flag Count','ECE Flag Count'
]

# Load QUBO selected features if available to filter
try:
    selected_indices = joblib.load("mlmodel/selected_features.pkl")
    # Mapping indices back to names based on train_model.py logic
    # In train_model.py, df is filtered by available_features first.
    # We will trust the scaler needs the SUBSET if selected_features.pkl implies it.
    # However, train_model.py says: X_selected = X.iloc[:, selected_indices]
    # So we need to select columns by index from the 'selected_features' list.
    
    # Actually, simpler: The scaler expects the REDUCED feature set.
    # We must filter 'selected_features' using 'selected_indices'.
    
    # Re-create the list used in training to map indices
    full_feature_list = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Mean',
        'Bwd Packet Length Mean', 'Flow Packets/s', 'FIN Flag Count', 'SYN Flag Count',
        'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
        'CWE Flag Count', 'ECE Flag Count', 'Label' # Label is not in X
    ][:17] # First 17 are features
    
    QUBO_FEATURES = [full_feature_list[i] for i in selected_indices if i < len(full_feature_list)]
    print(f"✅ Using {len(QUBO_FEATURES)} QUBO-selected features.")
    
except Exception as e:
    print(f"⚠️ Could not load selected_features.pkl. Using full set (may fail if model expects subset): {e}")
    QUBO_FEATURES = selected_features


def trigger_alert(src, dst, proto, length, reason, attack):
    print(f"🚨 ALERT: {src} → {dst} | proto:{proto} | len:{length} | reason:{reason} | attack:{attack}")

def generate_fake_ips(df):
    if "Src IP" not in df.columns:
        df["Src IP"] = [f"192.168.1.{random.randint(1,254)}" for _ in range(len(df))]
    if "Dst IP" not in df.columns:
        df["Dst IP"] = [f"10.0.0.{random.randint(1,254)}" for _ in range(len(df))]
    if "Protocol" not in df.columns:
        df["Protocol"] = np.random.choice([6, 17, 1], size=len(df))
    return df


attack_counter = 0
logs = []

for chunk in pd.read_csv(CSV_PATH, chunksize=CHUNK_SIZE, low_memory=False):
    chunk.columns = chunk.columns.str.strip()
    label_col = next((c for c in ["Label","label","Attack","attack","Class","class"] if c in chunk.columns), None)

    
    if label_col:
        attacks = chunk[chunk[label_col].astype(str).str.lower() != "benign"].copy()
    else:
        attacks = chunk[(chunk.get("SYN Flag Count",0) > 0) & (chunk.get("ACK Flag Count",0) == 0)].copy()

    if attacks.empty:
        continue

    if AMPLIFY_ATTACKS and label_col and AMPLIFY_LABEL:
        mask = attacks[label_col].astype(str).str.contains(AMPLIFY_LABEL, case=False, na=False)
        if mask.any():
            amplified = attacks[mask].sample(frac=AMPLIFY_FACTOR, replace=True)
            attacks = pd.concat([attacks, amplified], ignore_index=True)

 
    attacks = generate_fake_ips(attacks)

   
    for col in QUBO_FEATURES:
        if col not in attacks.columns:
            attacks[col] = 0
    
    # Select only the features expected by the model
    X = attacks[QUBO_FEATURES].fillna(0).replace([np.inf,-np.inf],0)
    X_iso = iso_scaler.transform(X)
    preds = iso_model.predict(X_iso)

   
    for i, (_, row) in enumerate(attacks.iterrows()):
        if preds[i] != -1:
            continue

       
        if SIMULATE_TIMING:
            time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
            if random.random() < BURST_PROB:
                print("🌊 Simulating DDoS burst...")
                for _ in range(BURST_SIZE):
                    time.sleep(BURST_DELAY)

        src = row["Src IP"]
        dst = row["Dst IP"]
        proto = row["Protocol"]
        length = int(row.get("Total Length of Fwd Packets", 0))
        reason = "Statistical anomaly"

       
        if have_classifier:
            X_clf = clf_scaler.transform(pd.DataFrame([X.iloc[i]]))
            pred = clf_model.predict(X_clf)[0]
            # Use dictionary lookup with default 'Unknown'
            attack_type = attack_labels.get(pred, "Unknown")
        else:
            attack_type = random.choice(list(attack_labels.values())) if isinstance(attack_labels, dict) else random.choice(attack_labels)

        if str(attack_type).upper() == "BENIGN":
            attack_type = random.choice(["DDoS", "PortScan", "Botnet", "Infiltration"])

        trigger_alert(src, dst, proto, length, reason, attack_type)

   
        if attack_type in ALERT_ATTACKS:
            send_telegram_alert(src, dst, attack_type, reason)

        
        cursor.execute("""
            INSERT INTO packets (timestamp, src_ip, dest_ip, protocol, length, flags, status, reason, attack_type)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            datetime.datetime.now(), src, dst, proto, length, 0, "Anomaly", reason, attack_type
        ))
        conn.commit()

        logs.append({
            "time": datetime.datetime.now(),
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto,
            "attack_type": attack_type
        })
        attack_counter += 1

print(f"✅ Simulation complete — total attacks simulated: {attack_counter}")
pd.DataFrame(logs).to_csv(DETECTIONS_LOG_CSV, index=False)
print(f"📁 Detection log saved: {DETECTIONS_LOG_CSV}")
conn.close()
