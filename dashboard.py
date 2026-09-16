#!/usr/bin/env python3
"""
dashboard.py -- Lightweight visualization dashboard for the Suricata NIDS
project. Reads eve.json directly (no database / Elastic Stack required)
and serves a single-page dashboard with alert charts using Chart.js.

Usage:
    pip install flask --break-system-packages
    sudo python3 dashboard.py --eve /var/log/suricata/eve.json
    # then open http://<sensor_ip>:5000 in a browser
"""

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)
EVE_PATH = "/var/log/suricata/eve.json"

PAGE = """
<!doctype html>
<html>
<head>
  <title>NIDS Alert Dashboard</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
  <style>
    body { font-family: Arial, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:24px; }
    h1 { color:#38bdf8; }
    .grid { display:grid; grid-template-columns:1fr 1fr; gap:24px; margin-top:24px; }
    .card { background:#1e293b; border-radius:12px; padding:16px; }
    .stat { font-size:2.2em; font-weight:bold; color:#38bdf8; }
  </style>
</head>
<body>
  <h1>Suricata NIDS Dashboard</h1>
  <p>Total alerts: <span class="stat" id="total">-</span></p>
  <div class="grid">
    <div class="card"><h3>Top Source IPs</h3><canvas id="ipChart"></canvas></div>
    <div class="card"><h3>Alerts by Signature</h3><canvas id="sigChart"></canvas></div>
    <div class="card"><h3>Alerts by Severity</h3><canvas id="sevChart"></canvas></div>
    <div class="card"><h3>Alerts Over Time (per minute)</h3><canvas id="timeChart"></canvas></div>
  </div>
<script>
async function load() {
  const res = await fetch('/api/stats');
  const data = await res.json();
  document.getElementById('total').innerText = data.total;

  new Chart(document.getElementById('ipChart'), {
    type: 'bar',
    data: { labels: data.top_ips.map(x => x[0]), datasets: [{ label: 'Alerts', data: data.top_ips.map(x => x[1]), backgroundColor:'#38bdf8' }] }
  });
  new Chart(document.getElementById('sigChart'), {
    type: 'bar',
    data: { labels: data.top_signatures.map(x => x[0]), datasets: [{ label: 'Alerts', data: data.top_signatures.map(x => x[1]), backgroundColor:'#f97316' }] },
    options: { indexAxis: 'y' }
  });
  new Chart(document.getElementById('sevChart'), {
    type: 'doughnut',
    data: { labels: Object.keys(data.severity), datasets: [{ data: Object.values(data.severity), backgroundColor:['#ef4444','#f59e0b','#22c55e'] }] }
  });
  new Chart(document.getElementById('timeChart'), {
    type: 'line',
    data: { labels: data.timeline.map(x => x[0]), datasets: [{ label: 'Alerts/min', data: data.timeline.map(x => x[1]), borderColor:'#a855f7', fill:false }] }
  });
}
load();
setInterval(load, 15000);
</script>
</body>
</html>
"""


def read_alerts(path):
    alerts = []
    try:
        with open(path, "r") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "alert":
                    alerts.append(event)
    except FileNotFoundError:
        pass
    return alerts


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/api/stats")
def stats():
    alerts = read_alerts(EVE_PATH)

    ip_counter = Counter(a.get("src_ip", "unknown") for a in alerts)
    sig_counter = Counter(a.get("alert", {}).get("signature", "unknown") for a in alerts)
    severity_counter = Counter(str(a.get("alert", {}).get("severity", "?")) for a in alerts)

    per_minute = defaultdict(int)
    for a in alerts:
        ts = a.get("timestamp")
        if ts:
            minute = ts[:16]  # YYYY-MM-DDTHH:MM
            per_minute[minute] += 1
    timeline = sorted(per_minute.items())[-30:]

    return jsonify({
        "total": len(alerts),
        "top_ips": ip_counter.most_common(8),
        "top_signatures": sig_counter.most_common(8),
        "severity": dict(severity_counter),
        "timeline": timeline,
    })


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--eve", default="/var/log/suricata/eve.json")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    EVE_PATH = args.eve
    app.run(host="0.0.0.0", port=args.port, debug=False)
