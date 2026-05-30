# CloudGuard AI — Incident Detection System

## ✅ STEP-BY-STEP SETUP (Windows / Mac / Linux)

### Step 1 — Install Python
Download Python 3.10+ from https://python.org
(During install, CHECK "Add Python to PATH")

---

### Step 2 — Extract This Project
Extract the ZIP to a folder, e.g.:
  C:\Projects\cloud_monitor\

---

### Step 3 — Open Terminal / Command Prompt
- Windows: Press Win+R → type `cmd` → Enter
- Mac/Linux: Open Terminal

Navigate to the project folder:
  cd C:\Projects\cloud_monitor

---

### Step 4 — Install Dependencies (ONE TIME ONLY)
  pip install -r requirements.txt

---

### Step 5 — Run the Application
  python app.py

You'll see:
  * Running on http://127.0.0.1:5000

---

### Step 6 — Open in Browser
Go to: http://localhost:5000

Login with:
  Username: admin
  Password: admin123

---

## 🚀 FEATURES
- Real-time CPU, Memory, Disk monitoring
- AI anomaly detection (Isolation Forest)
- Auto incident alerts (WARNING / CRITICAL)
- Incident log with resolve button
- Live performance charts
- Secure login with password hashing

## 📂 PROJECT STRUCTURE
cloud_monitor/
├── app.py              ← Main Flask application
├── requirements.txt    ← Python dependencies
├── templates/
│   ├── login.html      ← Login page
│   └── dashboard.html  ← Main dashboard
└── incident_monitoring.db  ← Created automatically on first run
