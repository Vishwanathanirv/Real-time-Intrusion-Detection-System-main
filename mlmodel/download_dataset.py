import os
import pandas as pd
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "..", "datasets")
os.makedirs(DATASET_DIR, exist_ok=True)

print("Creating a sample CICIDS2017 dataset for training...")

# Generate synthetic data for demonstration
# In production, download real CICIDS2017 dataset from:
# https://www.unb.ca/cic/datasets/ids-2017.html

np.random.seed(42)
n_samples = 10000

# Features
features = {
    'Destination Port': np.random.randint(1, 65535, n_samples),
    'Flow Duration': np.random.randint(1000, 1000000, n_samples),
    'Total Fwd Packets': np.random.randint(1, 100, n_samples),
    'Total Backward Packets': np.random.randint(1, 100, n_samples),
    'Total Length of Fwd Packets': np.random.randint(100, 10000, n_samples),
    'Total Length of Bwd Packets': np.random.randint(100, 10000, n_samples),
    'Fwd Packet Length Mean': np.random.uniform(10, 1500, n_samples),
    'Bwd Packet Length Mean': np.random.uniform(10, 1500, n_samples),
    'Flow Packets/s': np.random.uniform(0.1, 1000, n_samples),
    'FIN Flag Count': np.random.randint(0, 10, n_samples),
    'SYN Flag Count': np.random.randint(0, 10, n_samples),
    'RST Flag Count': np.random.randint(0, 10, n_samples),
    'PSH Flag Count': np.random.randint(0, 10, n_samples),
    'ACK Flag Count': np.random.randint(0, 100, n_samples),
    'URG Flag Count': np.random.randint(0, 5, n_samples),
    'CWE Flag Count': np.random.randint(0, 5, n_samples),
    'ECE Flag Count': np.random.randint(0, 5, n_samples),
}

# Create different attack patterns
attack_types = ['BENIGN', 'DoS Hulk', 'PortScan', 'DDoS', 'Bot', 'Web Attack']
labels = []

for i in range(n_samples):
    if i < 7000:
        labels.append('BENIGN')
    elif i < 7500:
        labels.append('DoS Hulk')
        features['SYN Flag Count'][i] = np.random.randint(20, 100)
        features['Flow Packets/s'][i] = np.random.uniform(1000, 10000)
    elif i < 8000:
        labels.append('PortScan')
        features['Destination Port'][i] = np.random.randint(1, 1024)
        features['SYN Flag Count'][i] = 1
    elif i < 8500:
        labels.append('DDoS')
        features['Flow Packets/s'][i] = np.random.uniform(5000, 20000)
    elif i < 9000:
        labels.append('Bot')
        features['Flow Duration'][i] = np.random.randint(5000000, 10000000)
    else:
        labels.append('Web Attack')
        features['Destination Port'][i] = np.random.choice([80, 443, 8080])

features['Label'] = labels

df = pd.DataFrame(features)

# Save dataset
output_path = os.path.join(DATASET_DIR, "CICIDS2017_full.csv")
df.to_csv(output_path, index=False)
print(f"✅ Sample dataset created at: {output_path}")
print(f"   Total samples: {len(df)}")
print(f"   Class distribution:\n{df['Label'].value_counts()}")
