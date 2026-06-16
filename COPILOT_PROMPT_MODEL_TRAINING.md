# Copilot Prompt for Model Training Setup

Copy and paste this prompt to GitHub Copilot on another system to set up the ML model training:

---

## 🤖 PROMPT FOR COPILOT:

```
I need to train a production-grade intrusion detection model using LightGBM + SVM ensemble on the CICIDS2017 dataset. Here are the exact requirements:

PROJECT CONTEXT:
- Dataset: CICIDS2017 (network intrusion detection dataset with 2.8M rows)
- Target: 15 attack types + BENIGN class (16 total classes)
- Current accuracy goal: 98.7%+ on imbalanced test data
- Features: 17 initial features reduced to 12 optimized features

REQUIRED IMPLEMENTATION:

1. **Data Preprocessing**:
   - Load CICIDS2017_full.csv from datasets/ folder
   - Handle missing values (drop or fill)
   - Clean infinite values
   - Separate features (X) and labels (y)
   - Stratified train/test split (80/20)

2. **Class Imbalance Handling**:
   - Apply SMOTE oversampling to training data ONLY
   - Target ~240,000 balanced samples
   - Calculate class weights for minority classes:
     * Heartbleed: ~708x weight
     * SQL Injection: ~375x weight
     * Infiltration: ~191x weight
   - Use class_weight='balanced' in both models

3. **Feature Engineering**:
   - Standardize features using StandardScaler
   - Compute feature importance from LightGBM
   - Select top 12 features based on importance ranking:
     * Flow Packets/s (importance: 9892)
     * Destination Port (4668)
     * Flow Duration (4599)
     * Fwd Packet Length Max (4476)
     * And 8 more top features
   - Save selected feature indices to selected_features.json

4. **Model Training - LightGBM**:
   - Algorithm: LightGBM Classifier
   - Hyperparameters:
     * n_estimators=300
     * learning_rate=0.05
     * max_depth=30
     * num_leaves=50
     * min_child_samples=20
     * subsample=0.8
     * colsample_bytree=0.8
     * class_weight='balanced'
     * random_state=42

5. **Model Training - SVM**:
   - Algorithm: Support Vector Classifier
   - Hyperparameters:
     * kernel='rbf'
     * C=10
     * gamma='scale'
     * class_weight='balanced'
     * probability=True (required for soft voting)
     * random_state=42

6. **Ensemble Strategy**:
   - Use VotingClassifier with soft voting
   - Weights: LightGBM=2, SVM=1 (2:1 ratio)
   - This combines probability predictions

7. **Threshold Optimization**:
   - For each of 16 classes:
     * Extract probability predictions on validation set
     * Test thresholds from 0.1 to 0.9 in steps of 0.05
     * Select threshold that maximizes F1-score
   - Save optimal thresholds to optimal_thresholds.pkl

8. **Validation Strategy**:
   - Training evaluation: On balanced SMOTE data
   - Final test evaluation: On ORIGINAL imbalanced test set (23,921 samples)
   - This tests real-world performance

9. **Save Model Artifacts**:
   - attack_classifier.pkl (ensemble model)
   - scaler.pkl (StandardScaler with 17 features)
   - attack_labels.pkl (LabelEncoder)
   - optimal_thresholds.pkl (per-class thresholds)
   - selected_features.json (indices of 12 selected features)

10. **Performance Metrics**:
    - Report training accuracy on balanced data
    - Report test accuracy on imbalanced data
    - Calculate Cohen's Kappa score (should be ~0.985)
    - Generate classification report with per-class metrics
    - Show confusion matrix

EXPECTED RESULTS:
- Training Accuracy: ~95.5%
- Test Accuracy: 98.7%+
- Cohen's Kappa: 0.985+
- DDoS/PortScan/DoS Hulk: 99-100% F1-score
- Bot: 96-97% F1-score
- Web attacks: 79-100% F1-score

FILE STRUCTURE:
Create/modify these files:
- mlmodel/train_classifier.py (main training script)
- mlmodel/attack_classifier.pkl (trained model)
- mlmodel/scaler.pkl (feature scaler)
- mlmodel/attack_labels.pkl (label encoder)
- mlmodel/optimal_thresholds.pkl (per-class thresholds)
- mlmodel/selected_features.json (feature indices)

DATASET LOCATION:
- Place CICIDS2017_full.csv in: datasets/CICIDS2017_full.csv
- If missing, download from Kaggle: https://www.kaggle.com/datasets/cicdataset/cicids2017

CRITICAL REQUIREMENTS:
1. SMOTE only on training data, test on original imbalanced data
2. Scale ALL 17 features first, THEN select 12 features
3. Use class weights to handle rare attacks
4. Optimize thresholds per class for better precision/recall balance
5. Use soft voting with 2:1 LightGBM/SVM weighting

Please generate the complete train_classifier.py file with all these requirements implemented.
```

---

## 📋 Quick Copy Version (Minimal Prompt):

```
Create train_classifier.py for intrusion detection using CICIDS2017 dataset:
- LightGBM (n=300, lr=0.05, depth=30) + SVM (C=10, RBF) ensemble with 2:1 voting
- SMOTE balancing on training only, test on imbalanced data
- Feature selection: 17→12 via importance ranking
- Per-class threshold optimization via F1-score
- Class weights for rare attacks (Heartbleed: 708x, SQL Injection: 375x)
- Target: 98.7%+ accuracy on imbalanced test set
- Save: classifier.pkl, scaler.pkl, labels.pkl, thresholds.pkl, selected_features.json
- Dataset: datasets/CICIDS2017_full.csv (2.8M rows, 16 classes)
```

---

## 🔍 Verification Steps After Training:

After Copilot generates the code, verify:

1. **Files Created** (check mlmodel/ folder):
   - ✅ attack_classifier.pkl (~46 MB)
   - ✅ scaler.pkl (~4 KB)
   - ✅ attack_labels.pkl (~1 KB)
   - ✅ optimal_thresholds.pkl (~1 KB)
   - ✅ selected_features.json (~200 bytes)

2. **Console Output Should Show**:
   ```
   Training Accuracy: 95.47%
   Test Accuracy (Imbalanced): 98.70%
   Cohen's Kappa: 0.9850
   
   Per-class F1-scores:
   DDoS: 1.00
   PortScan: 1.00
   DoS Hulk: 0.99
   BENIGN: 0.99
   ```

3. **Feature Selection Output**:
   ```
   Top 12 features selected:
   - Flow Packets/s (importance: 9892)
   - Destination Port (4668)
   - Flow Duration (4599)
   ...
   ```

4. **Threshold Optimization Output**:
   ```
   Optimal thresholds per class:
   BENIGN: 0.45
   DDoS: 0.30
   Bot: 0.25
   ...
   ```

---

## 🚨 Common Issues & Solutions:

### Issue: Low accuracy (<90%)
**Ask Copilot**: "The accuracy is below 90%. Increase n_estimators to 300, set learning_rate=0.05, and use class_weight='balanced' in both models."

### Issue: Training too slow
**Ask Copilot**: "Training takes too long. Use n_jobs=-1 for parallel processing and reduce dataset to 1M samples if needed."

### Issue: Imbalanced results (only predicts BENIGN)
**Ask Copilot**: "Model only predicts BENIGN class. Apply SMOTE with sampling_strategy='auto' and ensure class_weight='balanced' in both LightGBM and SVM."

### Issue: Feature dimension mismatch
**Ask Copilot**: "Getting dimension mismatch error. Ensure scaler fits 17 features, then select 12 features AFTER scaling."

---

## 📊 Expected Training Time:

- **Small dataset** (100K rows): 1-2 minutes
- **Full dataset** (2.8M rows): 5-10 minutes
- **Hardware**: Depends on CPU (faster with more cores)

---

## 🔗 Related Files to Share:

If Copilot needs additional context, share:
- requirements.txt (Python dependencies)
- analysis.py (shows how models are loaded)
- selected_features.json (feature indices format)

---

**After successful training, run**: `python train_classifier.py`

**Expected final output**: 
```
✅ Model training complete!
✅ Test Accuracy: 98.70%
✅ All artifacts saved in mlmodel/
```
