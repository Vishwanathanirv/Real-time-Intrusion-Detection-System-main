import os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import lightgbm as lgb
import joblib
from pipeline.quantum_pipeline import apply_quantum_feature_selection

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "..", "datasets", "CICIDS2017_full.csv")

def train_and_save():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)
    df.columns = df.columns.str.strip()

    required_features = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Mean',
        'Bwd Packet Length Mean', 'Flow Packets/s', 'FIN Flag Count', 'SYN Flag Count',
        'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
        'CWE Flag Count', 'ECE Flag Count', 'Label'
    ]

    available_features = [c for c in required_features if c in df.columns]
    df = df[available_features].copy()

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    X = df.drop(columns=['Label'], errors='ignore')
    y = df['Label'] if 'Label' in df.columns else np.zeros(len(df))

    # Encoding labels (Benign vs Attack)
    y_binary = np.where(y == "BENIGN", 1, -1) # 1 for normal, -1 for anomaly (IsolationForest convention)
    
    # Feature Selection using QUBO
    rf_selector = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    rf_selector.fit(X, y)
    feature_importance = rf_selector.feature_importances_
    corr_matrix = np.corrcoef(X.values, rowvar=False)

    selected_indices = apply_quantum_feature_selection(X.values, feature_importance, corr_matrix, k=15)
    
    # Ensure indices are valid
    if not selected_indices:
        selected_indices = list(range(X.shape[1])) # Fallback
    
    print(f"DEBUG: Selected {len(selected_indices)} features.")
    
    X_selected = X.iloc[:, selected_indices]
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_selected)
    print(f"DEBUG: Scaler expects {scaler.n_features_in_} features.")

    # Hybrid Ensemble Training
    
    # 1. Unsupervised: Isolation Forest (Anomaly Detection)
    iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
    iso_forest.fit(X_scaled)

    # 2. Supervised: LightGBM + SVM Ensemble (Attack Classification - Optimized)
    # Filter only attacks for classifier training or train on all with class weights?
    # We train on all to distinguish types. 
    # If dataset has string labels, we need to encode them for ensemble
    
    attack_labels = y.unique()
    label_map = {label: idx for idx, label in enumerate(attack_labels)}
    y_encoded = y.map(label_map)
    
    # Create LightGBM classifier with optimized hyperparameters
    lgb_classifier = lgb.LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        max_depth=30,
        num_leaves=50,
        min_child_samples=10,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,
        reg_lambda=0.1,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
        importance_type='gain'
    )
    
    # Create SVM classifier with optimized parameters
    svm_classifier = SVC(
        kernel='rbf',
        C=10.0,
        gamma='scale',
        probability=True,
        random_state=42,
        cache_size=500
    )
    
    # Create ensemble using VotingClassifier with weighted voting
    ensemble_classifier = VotingClassifier(
        estimators=[
            ('lgb', lgb_classifier),
            ('svm', svm_classifier)
        ],
        voting='soft',
        weights=[2, 1],
        n_jobs=-1
    )
    
    print("Training optimized LightGBM + SVM ensemble classifier...")
    ensemble_classifier.fit(X_scaled, y_encoded)

    # Artifact Saving
    joblib.dump(iso_forest, os.path.join(BASE_DIR, "anomaly_model.pkl"))
    joblib.dump(ensemble_classifier, os.path.join(BASE_DIR, "attack_classifier.pkl"))
    joblib.dump(scaler, os.path.join(BASE_DIR, "scaler.pkl"))
    joblib.dump(selected_indices, os.path.join(BASE_DIR, "selected_features.pkl"))
    joblib.dump(label_map, os.path.join(BASE_DIR, "attack_labels.pkl"))
    
    print("Training complete. LightGBM + SVM ensemble artifacts saved.")

if __name__ == "__main__":
    train_and_save()
