
import pandas as pd
from pathlib import Path

CSV_FOLDER = Path("TestingDatasets")
OUTPUT_CSV = Path("datasets/payload_data_CICIDS2017_17features.csv")


selected_features = [
    'Destination Port','Flow Duration','Total Fwd Packets','Total Backward Packets',
    'Total Length of Fwd Packets','Total Length of Bwd Packets',
    'Fwd Packet Length Mean','Bwd Packet Length Mean','Flow Packets/s',
    'FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count',
    'ACK Flag Count','URG Flag Count','CWE Flag Count','ECE Flag Count'
]


csv_files = sorted([p for p in CSV_FOLDER.rglob("*.csv")])
if not csv_files:
    raise SystemExit(f"No CSV files found in {CSV_FOLDER}.")

print(f"Found {len(csv_files)} CSV files. Reading...")

dfs = []
for p in csv_files:
    try:
        df = pd.read_csv(p, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)
        print("✅ Loaded", p.name)
    except Exception as e:
        print("⚠️ Skipping", p, "due to error:", e)

if not dfs:
    raise SystemExit("No valid CSVs loaded.")

full = pd.concat(dfs, ignore_index=True)
print("Combined shape:", full.shape)


label_col = next((c for c in ("Label","label","Attack","attack","Class","class","Labelled") if c in full.columns), None)
if label_col:
    print("✅ Found label column:", label_col)
else:
    print("⚠️ No label column found — creating default 'Label' = 'Unknown'")
    full["Label"] = "Unknown"
    label_col = "Label"


for col in selected_features:
    if col not in full.columns:
        print(f"⚠️ Missing feature {col}, filling zeros.")
        full[col] = 0


meta_cols = []
for meta in ('Source IP','Src IP','Destination IP','Dst IP','Protocol','Timestamp','Time','Flow ID'):
    if meta in full.columns:
        meta_cols.append(meta)

if not any(c for c in full.columns if "Src IP" in c or "Source IP" in c):
    print("⚠️ No source IP found — generating synthetic IPs.")
    full["Src IP"] = [f"192.168.1.{i%254+1}" for i in range(len(full))]
if not any(c for c in full.columns if "Dst IP" in c or "Destination IP" in c):
    print("⚠️ No destination IP found — generating synthetic IPs.")
    full["Dst IP"] = [f"10.0.0.{i%254+1}" for i in range(len(full))]
if "Protocol" not in full.columns:
    print("⚠️ No protocol column found — assigning random TCP/UDP/ICMP.")
    full["Protocol"] = pd.Series([6,17,1])[pd.Series(range(len(full))) % 3].values

cols_out = selected_features + ["Src IP","Dst IP","Protocol",label_col]

out_df = full[cols_out].replace([pd.NA, pd.NaT, float('inf'), float('-inf')], 0).fillna(0)
print("✅ Final dataset columns:", list(out_df.columns))


OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
out_df.to_csv(OUTPUT_CSV, index=False)
print(f"✅ Dataset ready: {OUTPUT_CSV} | Shape: {out_df.shape}")
