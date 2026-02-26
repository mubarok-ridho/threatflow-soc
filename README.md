# ⚡ ThreatFlow SOC

> Realtime Network Anomaly Detection powered by Ensemble ML + LLM Explanation

ThreatFlow SOC is a machine learning-based network anomaly detection system integrated with Suricata IDS, explained by LLM (Groq/Llama) to help SOC analysts understand threats quickly and accurately.

---

## 🏗️ Architecture

```
Network Traffic (ens160)
        ↓
   Suricata 7.x (IDS + EVE JSON)
        ↓
   NFStream (Feature Extraction)
        ↓
Ensemble ML Model:
  ├── XGBoost    (50%)
  ├── CNN        (20%)
  └── ResNet     (30%)
        ↓
   Threshold 0.80
        ↓
  ┌─────────────┐
  │   NORMAL    │ → Log
  └─────────────┘
  ┌─────────────┐
  │   ANOMALY   │ → Groq LLM (Llama 3.3 70B) → MITRE ATT&CK Mapping
  └─────────────┘
        ↓
   FastAPI + WebSocket
        ↓
   SOC Dashboard (Browser)
```

---

## 📋 Requirements

### Server (AlmaLinux 9.x / RHEL 9.x)
- AlmaLinux 9.7+
- Python 3.9+
- Suricata 7.x
- 4GB RAM minimum (8GB recommended for ML models)
- Active network interface (e.g. `ens160`)

### Client (Windows)
- Modern browser (Chrome/Edge/Firefox)
- PowerShell (for SCP file transfer)

---

## 🚀 Installation

### 1. Clone Repository

```bash
cd /opt
git clone https://github.com/mubarok-ridho/threatflow-soc.git
cd threatflow-soc
```

### 2. Install Python Dependencies

```bash
# Install pip if not available
sudo dnf install -y python3-pip

# Install all dependencies
pip3 install -r requirements.txt --timeout 300

# Install NFStream and WebSocket support
pip3 install nfstream
pip3 install 'uvicorn[standard]' websockets
```

> ⚠️ If `tensorflow-cpu` times out, install separately:
> ```bash
> pip3 install tensorflow-cpu==2.19.0 --timeout 300
> ```

### 3. Install & Configure Suricata

```bash
# Install Suricata
sudo dnf install -y epel-release
sudo dnf install -y suricata

# Download ET Free Rules
sudo suricata-update
```

#### 3a. Check Network Interface

Before configuration, find the active network interface name on your server:

```bash
ip link show
```

Example output:
```
1: lo: <LOOPBACK,UP,LOWER_UP> ...
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
```

Note the interface that is **UP** and connected to the network, e.g. `ens160`, `eth0`, `enp3s0`.

Verify the interface has an IP address:
```bash
ip addr show ens160
# or
nmcli device status
```

#### 3b. Set Interface in Suricata

Replace `ens160` with your actual interface name:

```bash
# Set interface in sysconfig
sudo sed -i 's/-i eth0/-i ens160/' /etc/sysconfig/suricata

# Verify
cat /etc/sysconfig/suricata
# Should show: OPTIONS="-i ens160 --user suricata"
```

Also set in `suricata.yaml`:
```bash
sudo sed -i 's/  - interface: eth0/  - interface: ens160/' /etc/suricata/suricata.yaml

# Verify
grep -n "interface: ens160" /etc/suricata/suricata.yaml
```

#### 3c. Enable EVE JSON Flow Output

Check if `flow` is already in EVE JSON types:
```bash
grep -n "^\s*- flow" /etc/suricata/suricata.yaml
```

If not found, add it:
```bash
sed -i 's/        - pgsql:/        - flow\n        - pgsql:/' /etc/suricata/suricata.yaml
```

#### 3d. Test Config & Start Suricata

```bash
# Test configuration first
sudo suricata -T -c /etc/suricata/suricata.yaml -v 2>&1 | tail -5
# Expected: "Configuration provided was successfully loaded"

# Fix log permissions
sudo chown -R suricata:suricata /var/log/suricata/

# Enable and start
sudo systemctl enable suricata
sudo systemctl daemon-reload
sudo systemctl start suricata
sudo systemctl status suricata
```

Verify `eve.json` is flowing:
```bash
sudo tail -f /var/log/suricata/eve.json
```

Expected output:
```json
{"timestamp":"2026-02-26T05:03:13+0700","event_type":"flow","src_ip":"192.168.145.1",...}
```

### 4. Copy Model Files

Model files are not included in the repo due to large file size. Copy them manually from your local machine:

```powershell
# From Windows PowerShell
scp -r D:\soc-ml-pipeline\models root@<SERVER_IP>:/opt/threatflow-soc/
```

Ensure the following files exist in the `models/` folder:
```
models/
├── xgboost_model.pkl
├── cnn_model.keras
├── resnet_best.keras
└── scaler.pkl
```

### 5. Create .env File

```bash
cat > /opt/threatflow-soc/.env << 'EOF'
GROQ_API_KEY=your_groq_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
EOF
```

Get a free Groq API key at: https://console.groq.com

### 6. Open Firewall Port

```bash
sudo firewall-cmd --add-port=8001/tcp --permanent
sudo firewall-cmd --reload
```

---

## ▶️ Running the System

### Terminal 1 — Verify Suricata is Running

```bash
sudo systemctl start suricata
sudo journalctl -u suricata -f
```

### Terminal 2 — Start Dashboard Server

```bash
cd /opt/threatflow-soc
uvicorn dashboard_server:app --host 0.0.0.0 --port 8001
```

Wait until you see:
```
✅ All models loaded successfully!
INFO: Uvicorn running on http://0.0.0.0:8001
```

### Browser (Windows/Client)

Open `dashboard.html` directly in your browser:
```
file:///D:/soc-ml-pipeline/dashboard.html
```

> ⚠️ Make sure the WebSocket URL in `dashboard.html` points to your server IP:
> ```javascript
> const wsUrl = `ws://<SERVER_IP>:8001/ws`;
> ```

The status indicator in the top right corner should show **CONNECTED** (green blinking dot).

---

## 📊 Dashboard Features

| Feature | Description |
|---------|-------------|
| **Live Event Feed** | Realtime stream of all analyzed flows |
| **Recent Anomalies** | Latest anomalies with scores |
| **Flow Timeline** | Normal vs anomaly chart per 5 seconds |
| **Score Distribution** | Histogram of ensemble score distribution |
| **Confidence Level** | Donut chart for HIGH/MEDIUM/LOW |
| **Anomaly Table** | Full details + LLM analysis per anomaly |
| **Toast Notification** | Pop-up alert for HIGH confidence anomalies |

---

## 🔧 Configuration

### Detection Threshold

Edit `config.py` to adjust detection sensitivity:

```python
ANOMALY_THRESHOLD = 0.80  # 0.0 - 1.0 (higher = more selective)
```

Recommendations:
- `0.70` — Sensitive, more alerts (good for strict monitoring)
- `0.80` — Balanced (default)
- `0.90` — Conservative, only highly suspicious traffic

### Ensemble Weights

```python
WEIGHT_XGBOOST = 0.50
WEIGHT_CNN     = 0.20
WEIGHT_RESNET  = 0.30
```

### NFStream Timeout

Edit `dashboard_server.py`:
```python
idle_timeout=30,    # flow considered complete after 30s idle
active_timeout=300, # max 5 minutes per flow
```

---

## 🧪 Testing

### Generate Normal Traffic

```bash
for i in {1..5}; do
    curl -s https://google.com > /dev/null
    curl -s https://github.com > /dev/null
    ping -c 3 8.8.8.8 > /dev/null
    sleep 3
done
```

### Simulate Anomalous Traffic

```bash
# Port scan simulation
for port in 22 23 80 443 3306 5432 8080 8443; do
    timeout 1 bash -c "echo > /dev/tcp/192.168.145.1/$port" 2>/dev/null
done

# Connection flood simulation
for i in {1..30}; do
    curl -s --max-time 1 http://192.168.145.1:$((RANDOM % 9000 + 1000)) > /dev/null 2>&1 &
done
wait
```

---

## 📁 Project Structure

```
threatflow-soc/
├── app/
│   ├── __init__.py
│   ├── gemini.py          # LLM explanation (Groq/Llama)
│   ├── main.py            # Main FastAPI app
│   ├── predictor.py       # Ensemble ML predictor
│   └── schemas.py         # Pydantic schemas
├── models/                # Model files (not committed to git)
│   ├── xgboost_model.pkl
│   ├── cnn_model.keras
│   ├── resnet_best.keras
│   └── scaler.pkl
├── config.py              # Global configuration
├── dashboard_server.py    # FastAPI + WebSocket server
├── dashboard.html         # SOC Dashboard (open in Windows browser)
├── nfstream_to_ml.py      # NFStream → ML pipeline (standalone)
├── eve_to_ml.py           # EVE JSON → ML pipeline (standalone)
├── requirements.txt
└── README.md
```

---

## 🔍 LLM Output Example

Every detected anomaly is analyzed by Llama 3.3 70B and produces:

```
🚨 [HIGH] Port Scanning Attack

📌 MITRE: T1046 - Network Service Discovery

📋 [EN] System detected anomaly with ensemble score 0.9916, indicating
        possible port scanning activity targeting multiple ports.

💥 [EN] Potential reconnaissance for further attacks on exposed services.

🛡️ [EN] Block source IP, enable IPS mode, review firewall rules.

🔍 Evidence: Destination_Port: 8080, Flow_Bytes_s: 61666.67, SYN_Flag_Count: 1
```

---

## ⚠️ Troubleshooting

### Suricata fails to start
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo journalctl -u suricata -n 50
```

### Models fail to load
```bash
# Check all model files exist
ls -la /opt/threatflow-soc/models/

# Test manually
cd /opt/threatflow-soc
python3 -c "from app.predictor import predictor; print('OK')"
```

### WebSocket not connecting
```bash
# Check server is running
ss -tlnp | grep 8001

# Check open ports
firewall-cmd --list-ports

# Open port if missing
sudo firewall-cmd --add-port=8001/tcp --permanent
sudo firewall-cmd --reload
```

### Groq rate limit exceeded
Groq free tier has a limit of 100k tokens/day. If exceeded, wait for the daily reset or upgrade to Dev Tier at: https://console.groq.com/settings/billing

---

## 📜 License

MIT License — Free to use for educational and research purposes.

---

## 👤 Author

**Ridho Mubarok** — SOC ML Pipeline Project
