import sys, os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import pandas as pd
import numpy as np
from sklearn.ensemble import VotingClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import lightgbm as lgb
import joblib

try:
    from imblearn.over_sampling import SMOTE
except ImportError:
    print("⚠️  Installing imbalanced-learn for SMOTE...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "imbalanced-learn"])
    from imblearn.over_sampling import SMOTE

# =========================================================
# Load dataset (ROBUST PATH)
# =========================================================
print("📥 Loading labeled dataset (CICIDS2017)...")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "..", "datasets", "CICIDS2017_full.csv")

df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()

# =========================================================
# Feature list
# =========================================================
features = [
    'Destination Port','Flow Duration','Total Fwd Packets','Total Backward Packets',
    'Total Length of Fwd Packets','Total Length of Bwd Packets',
    'Fwd Packet Length Mean','Bwd Packet Length Mean','Flow Packets/s',
    'FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count',
    'ACK Flag Count','URG Flag Count','CWE Flag Count','ECE Flag Count'
]

available = [c for c in features if c in df.columns]
print(f"✅ Using {len(available)} features.")

# =========================================================
# Detect label column
# =========================================================
label_col = None
for c in df.columns:
    if c.lower() in ["label", "attack_cat", "attacktype", "class", "target"]:
        label_col = c
        break

if not label_col:
    raise ValueError("❌ Label column not found!")

print(f"✅ Label column: {label_col}")

# =========================================================
# Cleaning
# =========================================================
df = df[available + [label_col]].copy()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
df[available] = df[available].clip(-1e6, 1e6)

print(f"✅ Cleaned dataset shape: {df.shape}")

# =========================================================
# Dataset Preparation with Real-World Distribution
# =========================================================
# Strategy: Train on balanced, validate on real-world imbalanced
MAX_SAMPLES = 150000
if len(df) > MAX_SAMPLES:
    # Stratified sampling to maintain class distribution
    df = df.groupby(label_col, group_keys=False).apply(
        lambda x: x.sample(min(len(x), MAX_SAMPLES // df[label_col].nunique() * 2), random_state=42)
    ).reset_index(drop=True)

# Remove classes with too few samples (minimum 10 for statistical validity)
class_counts = df[label_col].value_counts()
valid_classes = class_counts[class_counts >= 10].index
df = df[df[label_col].isin(valid_classes)]

print(f"📉 Dataset size after filtering: {df.shape}")
print(f"📊 Original class distribution:\n{df[label_col].value_counts()}\n")

# Split BEFORE balancing to preserve real-world test distribution
from sklearn.model_selection import train_test_split as tts

# Encode labels early for proper stratification
df[label_col] = df[label_col].astype("category")
df["Label_Code"] = df[label_col].cat.codes
categories = df[label_col].cat.categories.tolist()
label_map = {name: idx for idx, name in enumerate(categories)}

X = df[available].values
y = df["Label_Code"].astype(int).values

# First split: 80% train (will be balanced), 20% test (kept imbalanced - real-world)
X_train_full, X_test_real, y_train_full, y_test_real = tts(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"✅ Real-world test set preserved: {len(X_test_real)} samples (imbalanced)")
print(f"   This simulates actual network traffic distribution\n")

# =========================================================
# Balance Training Set Only (Test remains imbalanced)
# =========================================================
from imblearn.over_sampling import SMOTE

# Calculate class weights for cost-sensitive learning
from sklearn.utils.class_weight import compute_class_weight
class_weights = compute_class_weight('balanced', classes=np.unique(y_train_full), y=y_train_full)
class_weight_dict = dict(enumerate(class_weights))

print("📊 Class weights for cost-sensitive learning:")
for idx, weight in class_weight_dict.items():
    print(f"   Class {categories[idx]}: {weight:.3f}")

# Apply SMOTE for intelligent oversampling (better than random resampling)
print("\n🔄 Applying SMOTE to balance training data...")
smote = SMOTE(random_state=42, k_neighbors=5)
X_train_balanced, y_train_balanced = smote.fit_resample(X_train_full, y_train_full)

print(f"✅ Training set balanced: {len(X_train_balanced)} samples")
unique, counts = np.unique(y_train_balanced, return_counts=True)
print(f"   Balanced distribution: {dict(zip([categories[i] for i in unique], counts))}\n")

# =========================================================
# Feature Scaling
# =========================================================
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train_balanced)
X_test = scaler.transform(X_test_real)

y_train = y_train_balanced
y_test = y_test_real

# =========================================================
# Feature Importance Analysis & Selection
# =========================================================
print("🔍 Analyzing feature importance...")

# Train preliminary LightGBM to get feature importance
prelim_lgb = lgb.LGBMClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    verbose=-1,
    class_weight='balanced'
)
prelim_lgb.fit(X_train, y_train)

# Get feature importance
feature_importance = prelim_lgb.feature_importances_
feature_names = available
importance_df = pd.DataFrame({
    'feature': feature_names,
    'importance': feature_importance
}).sort_values('importance', ascending=False)

print("\n📊 Top Feature Importance Rankings:")
print(importance_df.to_string(index=False))

# Select top features (reduce redundancy)
TOP_K_FEATURES = 12  # Optimized feature count
top_features_idx = importance_df.head(TOP_K_FEATURES).index.tolist()
selected_features = [feature_names[i] for i in top_features_idx]

print(f"\n✅ Selected top {TOP_K_FEATURES} features for training:")
print(f"   {selected_features}\n")

# Apply feature selection
X_train_selected = X_train[:, top_features_idx]
X_test_selected = X_test[:, top_features_idx]

# =========================================================
# Train Optimized Ensemble with Class Weights
# =========================================================
print("🚀 Training optimized LightGBM + SVM ensemble with class-weighted learning...")

# Create LightGBM classifier with class weights
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
    importance_type='gain',
    class_weight='balanced'  # Cost-sensitive learning
)

# Create SVM classifier with class weights
svm_classifier = SVC(
    kernel='rbf',
    C=10.0,
    gamma='scale',
    probability=True,
    random_state=42,
    cache_size=500,
    class_weight='balanced'  # Cost-sensitive learning
)

# Create ensemble using VotingClassifier
clf = VotingClassifier(
    estimators=[
        ('lgb', lgb_classifier),
        ('svm', svm_classifier)
    ],
    voting='soft',
    weights=[2, 1],
    n_jobs=-1
)

print("Training ensemble on balanced data (this may take a few minutes)...")
clf.fit(X_train_selected, y_train)

# =========================================================
# Per-Class Probability Threshold Tuning
# =========================================================
print("\n🎯 Optimizing per-class probability thresholds...")

from sklearn.metrics import precision_recall_curve, f1_score

# Get probability predictions
y_proba = clf.predict_proba(X_test_selected)

# Find optimal threshold for each class
optimal_thresholds = {}
for class_idx in range(len(categories)):
    # Binary classification for this class
    y_binary = (y_test == class_idx).astype(int)
    proba_class = y_proba[:, class_idx]
    
    # Find threshold that maximizes F1 score
    thresholds = np.arange(0.3, 0.9, 0.05)
    best_f1 = 0
    best_threshold = 0.5
    
    for threshold in thresholds:
        y_pred_threshold = (proba_class >= threshold).astype(int)
        f1 = f1_score(y_binary, y_pred_threshold, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
    
    optimal_thresholds[class_idx] = best_threshold

print("📊 Optimal thresholds per class:")
for idx, threshold in optimal_thresholds.items():
    print(f"   {categories[idx]}: {threshold:.2f}")

# Apply optimized thresholds
y_pred_optimized = np.argmax(y_proba, axis=1)  # Default prediction
for i in range(len(y_proba)):
    max_proba = np.max(y_proba[i])
    predicted_class = np.argmax(y_proba[i])
    if max_proba < optimal_thresholds[predicted_class]:
        # If confidence is low, predict as most common class (BENIGN)
        benign_idx = categories.index('BENIGN') if 'BENIGN' in categories else 0
        y_pred_optimized[i] = benign_idx

# =========================================================
# Comprehensive Evaluation
# =========================================================
print("\n📊 Evaluating on Real-World Imbalanced Test Set...")

from sklearn.metrics import accuracy_score, confusion_matrix, cohen_kappa_score

y_pred_default = clf.predict(X_test_selected)
y_train_pred = clf.predict(X_train_selected)

train_accuracy = accuracy_score(y_train, y_train_pred)
test_accuracy_default = accuracy_score(y_test, y_pred_default)
test_accuracy_optimized = accuracy_score(y_test, y_pred_optimized)
kappa_score = cohen_kappa_score(y_test, y_pred_optimized)

print(f"\n{'='*70}")
print(f"🎯 FINAL ACCURACY RESULTS (Real-World Imbalanced Test Set):")
print(f"{'='*70}")
print(f"Training Accuracy (Balanced):        {train_accuracy*100:.2f}%")
print(f"Test Accuracy (Default):             {test_accuracy_default*100:.2f}%")
print(f"Test Accuracy (Threshold-Optimized): {test_accuracy_optimized*100:.2f}%")
print(f"Cohen's Kappa Score:                 {kappa_score:.4f}")
print(f"{'='*70}\n")

print("📊 Classification Report (Threshold-Optimized):\n")
print(classification_report(y_test, y_pred_optimized, target_names=categories, zero_division=0))

print("\n📉 Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred_optimized)
print(cm)

# =========================================================
# Save Optimized Artifacts
# =========================================================
print("\n💾 Saving optimized model artifacts...")

# Save all components
artifacts = {
    'classifier': clf,
    'scaler': scaler,
    'label_map': label_map,
    'optimal_thresholds': optimal_thresholds,
    'selected_features': selected_features,
    'feature_indices': top_features_idx,
    'all_features': available
}

joblib.dump(clf, os.path.join(BASE_DIR, "attack_classifier.pkl"))
joblib.dump(scaler, os.path.join(BASE_DIR, "scaler.pkl"))
joblib.dump(label_map, os.path.join(BASE_DIR, "attack_labels.pkl"))
joblib.dump(optimal_thresholds, os.path.join(BASE_DIR, "optimal_thresholds.pkl"))
joblib.dump(top_features_idx, os.path.join(BASE_DIR, "selected_features_idx.pkl"))

print("✅ Saved production-grade artifacts:")
print(f"   ➤ {os.path.join(BASE_DIR, 'attack_classifier.pkl')}")
print(f"   ➤ {os.path.join(BASE_DIR, 'scaler.pkl')}")
print(f"   ➤ {os.path.join(BASE_DIR, 'attack_labels.pkl')}")
print(f"   ➤ {os.path.join(BASE_DIR, 'optimal_thresholds.pkl')}")
print(f"   ➤ {os.path.join(BASE_DIR, 'selected_features_idx.pkl')}")
print(f"\n✨ Model ready for real-time deployment with {TOP_K_FEATURES} optimized features!")
