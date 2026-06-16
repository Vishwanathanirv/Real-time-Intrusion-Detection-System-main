import joblib
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SELECTED_INDICES_PATH = os.path.join(BASE_DIR, "selected_features.pkl")
OUTPUT_PATH = os.path.join(BASE_DIR, "..", "selected_features.json")

ALL_FEATURE_COLUMNS = [
    'Destination Port','Flow Duration','Total Fwd Packets','Total Backward Packets',
    'Total Length of Fwd Packets','Total Length of Bwd Packets',
    'Fwd Packet Length Mean','Bwd Packet Length Mean','Flow Packets/s',
    'FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count',
    'ACK Flag Count','URG Flag Count','CWE Flag Count','ECE Flag Count'
]

def export_features():
    try:
        indices = joblib.load(SELECTED_INDICES_PATH)
        selected_names = [ALL_FEATURE_COLUMNS[i] for i in indices if i < len(ALL_FEATURE_COLUMNS)]
        
        with open(OUTPUT_PATH, 'w') as f:
            json.dump(selected_names, f)
        
        print(f"Exported {len(selected_names)} features to {OUTPUT_PATH}")
    except Exception as e:
        print(f"Error exporting features: {e}")

if __name__ == "__main__":
    export_features()
