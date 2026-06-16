# Chanakya Shield - PacketEye Pro Setup Guide

Complete installation and execution guide for running the intrusion detection system.

---

## 🎯 System Requirements

- **OS**: Windows 10/11
- **Python**: 3.8+
- **Java**: JDK 17+
- **Node.js**: 16+
- **MySQL**: 8.0+
- **Maven**: 3.6+
- **RAM**: Minimum 8GB
- **Storage**: 5GB free space

---

## 📦 Step 1: Clone the Repository

```bash
git clone https://github.com/vishnuprahalathan/Chanakya_Shield
cd Chanakya_Shield
```

---

## 🗄️ Step 2: Setup MySQL Database

1. **Install MySQL** (if not installed): https://dev.mysql.com/downloads/installer/

2. **Create Database** (open MySQL Workbench or command line):
```sql
CREATE DATABASE IF NOT EXISTS packeteye;
USE packeteye;

CREATE TABLE packets (
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
);
```

3. **Create `.env` file** in project root:
```bash
# In Chanakya_Shield folder, create .env file
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=packeteye

# Optional: Telegram Alerts
BOT_TOKEN=your_bot_token
CHAT_ID=your_chat_id
```

---

## 🐍 Step 3: Setup Python Environment & Train ML Model

```bash
# Navigate to mlmodel directory
cd mlmodel

# Install Python dependencies
pip install -r ../requirements.txt

# Download CICIDS2017 Dataset
# Option 1: Use provided script
python download_dataset.py

# Option 2: Download manually from Kaggle
# https://www.kaggle.com/datasets/cicdataset/cicids2017
# Extract to: Chanakya_Shield/datasets/CICIDS2017_full.csv

# Train the LightGBM + SVM Ensemble Model
python train_classifier.py

# Expected Output:
# - Training Accuracy: 95.47%
# - Test Accuracy: 98.70%
# - Model files saved in mlmodel/ folder
```

**Note**: Training takes 5-10 minutes depending on your system.

---

## ☕ Step 4: Build Backend (Java Spring Boot)

```bash
# Navigate to backend directory
cd ../backend

# Build the project
mvn clean install -DskipTests

# Expected Output:
# BUILD SUCCESS
# JAR file: target/packeteye-0.0.1-SNAPSHOT.jar
```

---

## ⚛️ Step 5: Install Frontend Dependencies

```bash
# Navigate to frontend directory
cd ../frontend

# Install Node.js dependencies
npm install

# This will take 2-3 minutes
```

---

## 🚀 Step 6: Run the Complete System

Open **3 separate terminals** and run:

### Terminal 1 - Backend (Java Spring Boot)
```bash
cd Chanakya_Shield/backend
java -jar .\target\packeteye-0.0.1-SNAPSHOT.jar
```
**Expected**: Server starts on port 8080

### Terminal 2 - Frontend (React)
```bash
cd Chanakya_Shield/frontend
$env:BROWSER='none'
npm start
```
**Expected**: React app starts on port 3000

### Terminal 3 - Packet Analyzer (Python)
```bash
cd Chanakya_Shield/mlmodel
python analysis.py
```
**Expected**: "PacketEyePro Active. Press Ctrl+C to stop."

**Note**: Packet analyzer needs Npcap for live capture. If you get an error about winpcap, install Npcap from: https://npcap.com/#download

---

## 🧪 Step 7: Test with Simulated Attacks

Open a **4th terminal**:

```bash
cd Chanakya_Shield/Testing

# Run all attack simulations
python inject_attacks.py

# Or run specific attacks:
python inject_attacks.py ddos
python inject_attacks.py portscan
python inject_attacks.py dos-hulk
python inject_attacks.py ssh
python inject_attacks.py web
python inject_attacks.py bot
```

---

## 🌐 Step 8: Access the Dashboard

Open your browser and go to:
```
http://localhost:3000
```

You should see:
- Live packet dashboard
- Attack classifications (DDoS, PortScan, DoS, etc.)
- Real-time statistics
- Model accuracy: 98.70%

---

## 📊 System Components

### 1. **ML Model** (Python)
- **Algorithm**: LightGBM + SVM Ensemble
- **Accuracy**: 98.70% on real-world data
- **Features**: 12 optimized features (reduced from 17)
- **Techniques**: SMOTE balancing, class weights, threshold optimization
- **Files**: `attack_classifier.pkl`, `scaler.pkl`, `attack_labels.pkl`

### 2. **Backend** (Java Spring Boot)
- **Port**: 8080
- **API**: REST endpoints for packet data
- **Database**: MySQL connection via JPA
- **Endpoints**: 
  - GET `/api/packets` - Fetch all packets
  - POST `/api/packets` - Add new packet

### 3. **Frontend** (React)
- **Port**: 3000
- **Features**: Real-time dashboard, charts, attack visualization
- **Components**: Dashboard, PacketsTable, SimulateAttack

### 4. **Packet Analyzer** (Python)
- **Engine**: Scapy for packet capture
- **Processing**: Batch inference (10 packets/batch)
- **Detection**: Isolation Forest + LightGBM/SVM ensemble
- **Output**: Logs to MySQL database

---

## 🔧 Troubleshooting

### Issue: "Cannot find Python"
**Solution**: Add Python to PATH or use full path:
```bash
C:\Users\YourName\AppData\Local\Programs\Python\Python3XX\python.exe analysis.py
```

### Issue: "Port 8080 already in use"
**Solution**: Kill the process using port 8080:
```bash
netstat -ano | findstr :8080
taskkill /PID <process_id> /F
```

### Issue: "MySQL Access Denied"
**Solution**: Check `.env` file has correct password:
```
DB_PASSWORD=your_actual_mysql_password
```

### Issue: "Npcap not installed" (Packet Analyzer)
**Solution**: 
1. Install Npcap: https://npcap.com/#download
2. Enable "WinPcap compatibility mode" during installation
3. Restart packet analyzer

### Issue: "Model files not found"
**Solution**: Re-run training:
```bash
cd mlmodel
python train_classifier.py
```

---

## 📁 Project Structure

```
Chanakya_Shield/
├── backend/                 # Java Spring Boot
│   ├── src/main/java/
│   └── pom.xml
├── frontend/                # React Dashboard
│   ├── src/
│   └── package.json
├── mlmodel/                 # ML Training & Analysis
│   ├── train_classifier.py
│   ├── analysis.py
│   └── *.pkl (trained models)
├── datasets/                # CICIDS2017 Dataset
│   └── CICIDS2017_full.csv
├── Testing/                 # Attack Simulators
│   ├── inject_attacks.py
│   └── attack_simulator.py
├── database/               # SQL Scripts
│   └── create_table.sql
├── requirements.txt        # Python dependencies
└── .env                    # Environment variables
```

---

## 🎓 Attack Types Detected

| Attack | Precision | Recall | F1-Score |
|--------|-----------|--------|----------|
| BENIGN | 99% | 98% | 99% |
| DDoS | 100% | 100% | 100% |
| DoS Hulk | 99% | 99% | 99% |
| PortScan | 100% | 100% | 100% |
| DoS Slowloris | 100% | 99% | 100% |
| SSH-Patator | 100% | 100% | 100% |
| Bot | 96% | 99% | 97% |
| Web Attack | 79-100% | Various | Various |

---

## 🔐 Production Deployment

For production use:
1. Change MySQL password in `.env`
2. Enable HTTPS for frontend
3. Add authentication to backend API
4. Configure Telegram alerts
5. Set up log rotation
6. Use process manager (PM2/systemd)

---

## 📞 Support

- **GitHub**: https://github.com/vishnuprahalathan/Chanakya_Shield
- **Issues**: Report bugs via GitHub Issues
- **Documentation**: See MODEL_IMPROVEMENTS.md for technical details

---

## ✅ Quick Start Summary

```bash
# 1. Setup Database
CREATE DATABASE packeteye;

# 2. Install Dependencies
pip install -r requirements.txt
cd backend && mvn clean install -DskipTests
cd ../frontend && npm install

# 3. Train Model
cd ../mlmodel && python train_classifier.py

# 4. Run (3 terminals)
Terminal 1: cd backend && java -jar target/packeteye-0.0.1-SNAPSHOT.jar
Terminal 2: cd frontend && npm start
Terminal 3: cd mlmodel && python analysis.py

# 5. Access Dashboard
http://localhost:3000

# 6. Test Attacks
cd Testing && python inject_attacks.py
```

---

**🎉 You're all set! The intrusion detection system is now running with 98.70% accuracy!**
