from scapy.all import sniff, IP, TCP
import mysql.connector
import datetime
import joblib
import pandas as pd
import numpy as np
import requests
import warnings
import os

import os
from dotenv import load_dotenv

warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(BASE_DIR), ".env"))

# Configuration
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")
ALERT_ATTACKS = ["DoS Hulk", "PortScan", "DDoS", "Infiltration", "Bot", "Web Attack"] 

def load_models():
    try:
        iso_model = joblib.load(os.path.join(BASE_DIR, "anomaly_model.pkl"))
        ensemble_model = joblib.load(os.path.join(BASE_DIR, "attack_classifier.pkl"))
        scaler = joblib.load(os.path.join(BASE_DIR, "scaler.pkl"))
        label_map = joblib.load(os.path.join(BASE_DIR, "attack_labels.pkl"))
        
        # Load optimized inference components
        try:
            optimal_thresholds = joblib.load(os.path.join(BASE_DIR, "optimal_thresholds.pkl"))
            selected_features_idx = joblib.load(os.path.join(BASE_DIR, "selected_features_idx.pkl"))
        except FileNotFoundError:
            print("⚠️  Using default thresholds and all features")
            optimal_thresholds = None
            selected_features_idx = None
        
        # Invert label map for decoding
        inv_label_map = {v: k for k, v in label_map.items()}
        
        return iso_model, ensemble_model, scaler, inv_label_map, optimal_thresholds, selected_features_idx
    except FileNotFoundError as e:
        print(f"Error loading models: {e}")
        return None, None, None, None, None, None

iso_model, ensemble_model, scaler, inv_label_map, optimal_thresholds, selected_features_idx = load_models()

def send_telegram_alert(src_ip, dest_ip, attack_type, reason):
    try:
        message = (
            f"PacketEyePro Alert\n"
            f"Time: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n"
            f"Type: {attack_type}\n"
            f"Source: {src_ip}\n"
            f"Destination: {dest_ip}\n"
            f"Reason: {reason}"
        )
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": CHAT_ID, "text": message}, timeout=3)
    except Exception:
        pass

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "packeteye")
    )

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME,
        src_ip VARCHAR(45),
        dest_ip VARCHAR(45),
        protocol VARCHAR(10),
        length INT,
        flags INT,
        status VARCHAR(20),
        reason VARCHAR(255),
        attack_type VARCHAR(50)
    )
    """)
    conn.commit()
    conn.close()

init_db()

ALL_FEATURE_COLUMNS = [
    'Destination Port','Flow Duration','Total Fwd Packets','Total Backward Packets',
    'Total Length of Fwd Packets','Total Length of Bwd Packets',
    'Fwd Packet Length Mean','Bwd Packet Length Mean','Flow Packets/s',
    'FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count',
    'ACK Flag Count','URG Flag Count','CWE Flag Count','ECE Flag Count'
]

# Track flows for real feature extraction
flow_stats = {}

def extract_features(packet):
    if not packet.haslayer(IP):
        return None

    length = len(packet)
    flags = int(packet[TCP].flags) if packet.haslayer(TCP) else 0
    src_ip = packet[IP].src
    dest_ip = packet[IP].dst
    flow_key = tuple(sorted([src_ip, dest_ip]))

    now = datetime.datetime.now().timestamp()
    if flow_key not in flow_stats:
        flow_stats[flow_key] = {'start': now, 'fwd': 0, 'bwd': 0, 'len_fwd': 0, 'len_bwd': 0}
    
    stats = flow_stats[flow_key]
    duration = max(1, int((now - stats['start']) * 1000000)) # in microseconds
    
    if src_ip == flow_key[0]:
        stats['fwd'] += 1
        stats['len_fwd'] += length
    else:
        stats['bwd'] += 1
        stats['len_bwd'] += length

    return {
        'Destination Port': packet[TCP].dport if packet.haslayer(TCP) else 0,
        'Flow Duration': duration, 
        'Total Fwd Packets': stats['fwd'],
        'Total Backward Packets': stats['bwd'],
        'Total Length of Fwd Packets': stats['len_fwd'],
        'Total Length of Bwd Packets': stats['len_bwd'],
        'Fwd Packet Length Mean': stats['len_fwd'] / max(1, stats['fwd']),
        'Bwd Packet Length Mean': stats['len_bwd'] / max(1, stats['bwd']),
        'Flow Packets/s': (stats['fwd'] + stats['bwd']) / max(0.001, (now - stats['start'])),
        'FIN Flag Count': flags & 0x01,
        'SYN Flag Count': (flags & 0x02) >> 1,
        'RST Flag Count': (flags & 0x04) >> 2,
        'PSH Flag Count': (flags & 0x08) >> 3,
        'ACK Flag Count': (flags & 0x10) >> 4,
        'URG Flag Count': (flags & 0x20) >> 5,
        'CWE Flag Count': 0,
        'ECE Flag Count': (flags & 0x40) >> 6,
    }

# Packet batch buffer for efficient inference
packet_buffer = []
BATCH_SIZE = 10  # Process packets in batches
last_inference_time = datetime.datetime.now()

def process_packet(packet):
    global packet_buffer, last_inference_time
    
    if not iso_model:
        return

    try:
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)
        flags = int(packet[TCP].flags) if packet.haslayer(TCP) else 0
        timestamp = datetime.datetime.now()

        features = extract_features(packet)
        if not features:
            return

        # Add to batch buffer
        packet_buffer.append({
            'features': features,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'proto': proto,
            'length': length,
            'flags': flags,
            'timestamp': timestamp
        })
        
        # Process batch when buffer is full or timeout
        time_since_last = (datetime.datetime.now() - last_inference_time).total_seconds()
        
        if len(packet_buffer) >= BATCH_SIZE or time_since_last > 1.0:
            process_batch()
            last_inference_time = datetime.datetime.now()

    except Exception:
        pass

def process_batch():
    """Optimized batch processing for real-time inference"""
    global packet_buffer
    
    if not packet_buffer:
        return
    
    batch = packet_buffer.copy()
    packet_buffer = []
    
    try:
        # Extract features from batch
        features_list = [item['features'] for item in batch]
        df_batch = pd.DataFrame(features_list, columns=ALL_FEATURE_COLUMNS)
        
        # Batch scaling FIRST (on all 17 features)
        X_scaled = scaler.transform(df_batch)
        
        # THEN apply feature selection if available
        if selected_features_idx is not None:
            X_scaled = X_scaled[:, selected_features_idx]
        
        # Batch anomaly detection
        anomaly_scores = iso_model.predict(X_scaled)
        
        # Batch classification with probability thresholds
        if optimal_thresholds is not None:
            y_proba = ensemble_model.predict_proba(X_scaled)
            predictions = []
            
            for proba in y_proba:
                predicted_class = np.argmax(proba)
                max_proba = np.max(proba)
                
                # Apply per-class threshold
                threshold = optimal_thresholds.get(predicted_class, 0.5)
                if max_proba < threshold:
                    # Low confidence - predict as BENIGN
                    benign_idx = list(inv_label_map.values()).index('BENIGN') if 'BENIGN' in inv_label_map.values() else 0
                    predictions.append(benign_idx)
                else:
                    predictions.append(predicted_class)
        else:
            predictions = ensemble_model.predict(X_scaled)
        
        # Process results
        conn = get_db_connection()
        cursor = conn.cursor()
        
        for i, item in enumerate(batch):
            anomaly_score = anomaly_scores[i]
            pred_idx = predictions[i]
            attack_type = inv_label_map.get(pred_idx, "Unknown")
            
            status = "Normal"
            reason = ""
            
            if anomaly_score == -1:
                if attack_type == "BENIGN":
                    status = "Normal"
                    reason = "Background Noise (Filtered)"
                else:
                    status = "Anomaly"
                    reason = f"Classified as {attack_type}"
                    
                    if attack_type in ALERT_ATTACKS:
                        send_telegram_alert(item['src_ip'], item['dest_ip'], attack_type, reason)
            
            # Insert to database
            cursor.execute("""
                INSERT INTO packets
                (timestamp, src_ip, dest_ip, protocol, length, flags, status, reason, attack_type)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                item['timestamp'], item['src_ip'], item['dest_ip'], str(item['proto']),
                item['length'], item['flags'], status, reason, attack_type
            ))
        
        conn.commit()
        conn.close()
        
        # Print summary
        anomalies = sum(1 for s in anomaly_scores if s == -1)
        if anomalies > 0:
            print(f"[{datetime.datetime.now()}] Processed batch: {len(batch)} packets, {anomalies} anomalies detected")
    
    except Exception as e:
        print(f"Batch processing error: {e}")
        pass

if __name__ == "__main__":
    print("PacketEyePro Active. Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)
