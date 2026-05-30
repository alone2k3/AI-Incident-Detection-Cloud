from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import psutil, sqlite3, hashlib, random, smtplib, threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import pandas as pd
from sklearn.ensemble import IsolationForest

app = Flask(__name__)
app.secret_key = 'cloud_monitor_secret_2024'

# ── Email Config ──────────────────────────────────────────────────────────────
EMAIL_CONFIG = {
    'enabled':       True,
    'sender_email':  'punithan12.2k3@gmail.com',
    'sender_pass':   'rnkj smdw typf efaw',
    'receiver_email':'punithanamose2003@gmail.com',
    'smtp_server':   'smtp.gmail.com',
    'smtp_port':     587,
}
_last_email_time = {}

def send_email_alert(severity, cpu, memory, disk, message):
    if not EMAIL_CONFIG['enabled']: return
    import time
    now = time.time()
    if now - _last_email_time.get(severity, 0) < 300: return
    _last_email_time[severity] = now
    def _send():
        try:
            color = '#ef4444' if severity == 'CRITICAL' else '#f59e0b'
            html = f"""<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;border:1px solid #ddd;border-radius:10px;overflow:hidden">
              <div style="background:{color};padding:20px;text-align:center">
                <h1 style="color:white;margin:0;">⚠ {severity} ALERT</h1>
                <p style="color:white;margin:8px 0 0;opacity:0.9">CloudGuard AI Monitoring System</p>
              </div>
              <div style="padding:24px;background:#f9f9f9">
                <p><strong>AI Engine has detected an anomaly in your cloud infrastructure.</strong></p>
                <table style="width:100%;border-collapse:collapse;margin:16px 0">
                  <tr><td style="padding:10px;border:1px solid #eee;color:#666">Time</td><td style="padding:10px;border:1px solid #eee;font-weight:bold">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                  <tr><td style="padding:10px;border:1px solid #eee;color:#666">Severity</td><td style="padding:10px;border:1px solid #eee;font-weight:bold;color:{color}">{severity}</td></tr>
                  <tr><td style="padding:10px;border:1px solid #eee;color:#666">CPU</td><td style="padding:10px;border:1px solid #eee;font-weight:bold">{cpu:.1f}%</td></tr>
                  <tr><td style="padding:10px;border:1px solid #eee;color:#666">Memory</td><td style="padding:10px;border:1px solid #eee;font-weight:bold">{memory:.1f}%</td></tr>
                  <tr><td style="padding:10px;border:1px solid #eee;color:#666">Message</td><td style="padding:10px;border:1px solid #eee">{message}</td></tr>
                </table>
                <div style="background:#{'fff3cd' if severity=='WARNING' else 'fde8e8'};border:1px solid {color};border-radius:6px;padding:12px">
                  <p style="margin:0;font-size:13px;">{'🔴 CRITICAL: Immediate action required.' if severity=='CRITICAL' else '🟡 WARNING: Monitor closely.'}</p>
                </div>
              </div>
            </div>"""
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[CloudGuard] {severity} ALERT — Anomaly Detected"
            msg['From'] = EMAIL_CONFIG['sender_email']
            msg['To']   = EMAIL_CONFIG['receiver_email']
            msg.attach(MIMEText(html, 'html'))
            s = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
            s.starttls()
            s.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_pass'])
            s.sendmail(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['receiver_email'], msg.as_string())
            s.quit()
            print(f"[EMAIL] Sent: {severity}")
        except Exception as e:
            print(f"[EMAIL ERROR] {e}")
    threading.Thread(target=_send, daemon=True).start()

# ── Database ──────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect('incident_monitoring.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT DEFAULT 'user')''')
    c.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, cpu REAL, memory REAL, disk REAL, network REAL,
        severity TEXT, message TEXT, status TEXT DEFAULT 'open')''')
    c.execute('''CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, cpu REAL, memory REAL, disk REAL, network REAL)''')
    pw = hashlib.sha256('admin123'.encode()).hexdigest()
    try: c.execute("INSERT INTO users (username,password,role) VALUES (?,?,?)", ('admin', pw, 'admin'))
    except: pass
    conn.commit(); conn.close()

# ── AI Model ──────────────────────────────────────────────────────────────────
_train = pd.DataFrame({
    'cpu':    [random.uniform(10,60) for _ in range(200)],
    'memory': [random.uniform(20,65) for _ in range(200)],
    'disk':   [random.uniform(10,50) for _ in range(200)],
    'network':[random.uniform(0,30)  for _ in range(200)],
})
iso_model = IsolationForest(contamination=0.1, random_state=42)
iso_model.fit(_train)

def detect_anomaly(cpu, mem, disk, net):
    s = pd.DataFrame({'cpu':[cpu],'memory':[mem],'disk':[disk],'network':[net]})
    pred = iso_model.predict(s)[0]
    if cpu > 90 or mem > 90:
        return True, 'CRITICAL', f"Critical: CPU={cpu:.1f}%, MEM={mem:.1f}%"
    if cpu > 75 or mem > 80:
        return True, 'WARNING',  f"High usage: CPU={cpu:.1f}%, MEM={mem:.1f}%"
    if pred == -1 and (cpu > 60 or mem > 70):
        return True, 'WARNING',  f"AI anomaly: CPU={cpu:.1f}%, MEM={mem:.1f}%"
    return False, 'NORMAL', 'System operating normally'

# ── Page Routes ───────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['user'])

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        conn = sqlite3.connect('incident_monitoring.db')
        user = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (username,password)).fetchone()
        conn.close()
        if user:
            session['user'] = username
            session['role'] = user[3]
            return redirect(url_for('index'))
        error = 'Invalid credentials. Try admin / admin123'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))

@app.route('/monitoring')
def monitoring():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('monitoring.html', username=session['user'])

@app.route('/ai-detection')
def ai_detection():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('ai_detection.html', username=session['user'])

@app.route('/incidents-page')
def incidents_page():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('incidents.html', username=session['user'])

@app.route('/alerts-page')
def alerts_page():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('alerts.html', username=session['user'])

# ── API Routes ────────────────────────────────────────────────────────────────
@app.route('/api/metrics')
def api_metrics():
    if 'user' not in session: return jsonify({'error':'Unauthorized'}), 401
    cpu  = psutil.cpu_percent(interval=0.1)
    mem  = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    net  = psutil.net_io_counters()
    network = round((net.bytes_sent + net.bytes_recv) / 1024 / 1024 % 100, 2)
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    anomaly, severity, message = detect_anomaly(cpu, mem, disk, network)
    conn = sqlite3.connect('incident_monitoring.db')
    c = conn.cursor()
    c.execute("INSERT INTO metrics (timestamp,cpu,memory,disk,network) VALUES (?,?,?,?,?)",
              (ts, cpu, mem, disk, network))
    if anomaly:
        c.execute("INSERT INTO incidents (timestamp,cpu,memory,disk,network,severity,message) VALUES (?,?,?,?,?,?,?)",
                  (ts, cpu, mem, disk, network, severity, message))
        send_email_alert(severity, cpu, mem, disk, message)
    conn.commit(); conn.close()
    return jsonify({'timestamp':ts,'cpu':cpu,'memory':mem,'disk':disk,
                    'network':network,'anomaly':anomaly,'severity':severity,'message':message})

@app.route('/api/incidents')
def api_incidents():
    if 'user' not in session: return jsonify({'error':'Unauthorized'}), 401
    conn = sqlite3.connect('incident_monitoring.db')
    rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return jsonify([{'id':r[0],'timestamp':r[1],'cpu':r[2],'memory':r[3],
                     'disk':r[4],'network':r[5],'severity':r[6],'message':r[7],'status':r[8]} for r in rows])

@app.route('/api/history')
def api_history():
    if 'user' not in session: return jsonify({'error':'Unauthorized'}), 401
    conn = sqlite3.connect('incident_monitoring.db')
    rows = conn.execute("SELECT timestamp,cpu,memory,disk FROM metrics ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    rows = list(reversed(rows))
    return jsonify({'labels':[r[0][-8:] for r in rows],
                    'cpu':   [r[1] for r in rows],
                    'memory':[r[2] for r in rows],
                    'disk':  [r[3] for r in rows]})

@app.route('/api/stats')
def api_stats():
    if 'user' not in session: return jsonify({'error':'Unauthorized'}), 401
    conn = sqlite3.connect('incident_monitoring.db')
    total    = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM incidents WHERE severity='CRITICAL'").fetchone()[0]
    warning  = conn.execute("SELECT COUNT(*) FROM incidents WHERE severity='WARNING'").fetchone()[0]
    conn.close()
    return jsonify({'total':total,'critical':critical,'warning':warning})

@app.route('/api/resolve/<int:iid>', methods=['POST'])
def resolve_incident(iid):
    if 'user' not in session: return jsonify({'error':'Unauthorized'}), 401
    conn = sqlite3.connect('incident_monitoring.db')
    conn.execute("UPDATE incidents SET status='resolved' WHERE id=?", (iid,))
    conn.commit(); conn.close()
    return jsonify({'success':True})

@app.route('/api/processes')
def api_processes():
    if 'user' not in session: return jsonify({'error':'Unauthorized'}), 401
    procs = []
    for p in psutil.process_iter(['pid','name','cpu_percent','memory_info']):
        try:
            mem_mb = round(p.info['memory_info'].rss/1024/1024, 1)
            cpu    = round(p.info['cpu_percent'], 1)
            if cpu > 0 or mem_mb > 10:
                procs.append({'name':p.info['name'],'cpu':cpu,'memory':mem_mb})
        except: pass
    procs.sort(key=lambda x: x['cpu'], reverse=True)
    return jsonify(procs[:10])

@app.route('/api/test-email', methods=['POST'])
def test_email():
    if 'user' not in session: return jsonify({'error':'Unauthorized'}), 401
    send_email_alert.__globals__['_last_email_time'] = {}  # reset cooldown for test
    send_email_alert('WARNING', 55.0, 60.0, 40.0, 'TEST alert from CloudGuard AI')
    return jsonify({'success':True,'message':'Test email sent!'})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
