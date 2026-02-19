#!/usr/bin/env python3
"""
sentinel_server.py  —  NetSentinel Central Command Server

Receives encrypted alerts from agents, serves a real-time GUI dashboard.

Dependencies:
    pip install flask flask-socketio gevent gevent-websocket cryptography

Run:
    python3 sentinel_server.py [--config sentinel_config.json]
"""

import argparse
import json
import ssl
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

try:
    from flask import Flask, request, jsonify, render_template_string
    from flask_socketio import SocketIO, emit
except ImportError:
    raise SystemExit("[!] Run:  pip install flask flask-socketio gevent gevent-websocket")

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════

def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"[!] Config not found: {path}  —  run gen_certs.py first.")
    return json.loads(p.read_text())


# ══════════════════════════════════════════════════════════════════════════════
# STATE
# ══════════════════════════════════════════════════════════════════════════════

MAX_ALERTS   = 2000   # rolling in-memory buffer
alerts_store: deque  = deque(maxlen=MAX_ALERTS)
alerts_lock           = threading.Lock()

agents: dict[str, dict] = {}   # agent_id → {hostname, last_seen, alert_count, ip}
agents_lock = threading.Lock()

category_counts: dict[str, int] = defaultdict(int)
level_counts:    dict[str, int] = defaultdict(int)
level_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ══════════════════════════════════════════════════════════════════════════════
# FLASK APP
# ══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.config["SECRET_KEY"] = uuid.uuid4().hex

socketio = SocketIO(
    app,
    async_mode="gevent",
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
)


# ── auth decorator ─────────────────────────────────────────────────────────────

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if key != app.config["API_KEY"]:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


# ── REST endpoints ─────────────────────────────────────────────────────────────

@app.route("/api/alert", methods=["POST"])
@require_api_key
def receive_alert():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Bad request"}), 400

    required = {"level", "category", "message", "agent_id", "hostname"}
    if not required.issubset(data):
        return jsonify({"error": "Missing fields"}), 400

    alert = {
        "id":        uuid.uuid4().hex[:12],
        "ts":        datetime.now(timezone.utc).isoformat(),
        "level":     data["level"],
        "category":  data["category"],
        "message":   data["message"],
        "src":       data.get("src", ""),
        "agent_id":  data["agent_id"],
        "hostname":  data["hostname"],
    }

    with alerts_lock:
        alerts_store.appendleft(alert)
        category_counts[alert["category"]] += 1
        level_counts[alert["level"]]       += 1

    # Update agent registry
    agent_ip = request.remote_addr
    with agents_lock:
        if alert["agent_id"] not in agents:
            agents[alert["agent_id"]] = {
                "hostname":    alert["hostname"],
                "first_seen":  alert["ts"],
                "alert_count": 0,
                "ip":          agent_ip,
            }
        agents[alert["agent_id"]]["last_seen"]    = alert["ts"]
        agents[alert["agent_id"]]["alert_count"] += 1

    # Push to dashboard in real time
    socketio.emit("alert", alert)
    socketio.emit("stats", _build_stats())

    return jsonify({"ok": True, "id": alert["id"]}), 201


@app.route("/api/agent/heartbeat", methods=["POST"])
@require_api_key
def heartbeat():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "Missing agent_id"}), 400

    with agents_lock:
        if agent_id not in agents:
            agents[agent_id] = {
                "hostname":    data.get("hostname", "unknown"),
                "first_seen":  datetime.now(timezone.utc).isoformat(),
                "alert_count": 0,
                "ip":          request.remote_addr,
            }
        agents[agent_id]["last_seen"] = datetime.now(timezone.utc).isoformat()
        agents[agent_id]["ip"]        = request.remote_addr

    socketio.emit("agents", _build_agents())
    return jsonify({"ok": True}), 200


@app.route("/api/state", methods=["GET"])
@require_api_key
def get_state():
    with alerts_lock:
        recent = list(alerts_store)[:200]
    return jsonify({"alerts": recent, "stats": _build_stats(), "agents": _build_agents()})


def _build_stats() -> dict:
    with alerts_lock:
        return {
            "total":      sum(level_counts.values()),
            "by_level":   dict(level_counts),
            "by_category": dict(category_counts),
        }

def _build_agents() -> list:
    now = time.time()
    result = []
    with agents_lock:
        for aid, info in agents.items():
            try:
                last = datetime.fromisoformat(info["last_seen"]).timestamp()
                online = (now - last) < 90
            except Exception:
                online = False
            result.append({**info, "agent_id": aid, "online": online})
    return result


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD  (served as a single-file SPA)
# ══════════════════════════════════════════════════════════════════════════════

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>NetSentinel — Command Centre</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Orbitron:wght@700;900&display=swap" rel="stylesheet"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.6.1/socket.io.min.js"></script>
<style>
  :root {
    --bg0:       #03050a;
    --bg1:       #080d16;
    --bg2:       #0d1520;
    --bg3:       #121d2b;
    --border:    #1a2d45;
    --accent:    #00d4ff;
    --accent2:   #00ff9d;
    --warn:      #ffcc00;
    --danger:    #ff3c5a;
    --critical:  #ff00aa;
    --muted:     #3a5470;
    --text:      #c8dff0;
    --textdim:   #5a7a99;
    --glow:      0 0 12px rgba(0,212,255,.35);
    --glow2:     0 0 12px rgba(0,255,157,.35);
    --font-mono: 'Share Tech Mono', monospace;
    --font-ui:   'Rajdhani', sans-serif;
    --font-hd:   'Orbitron', sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg0);
    color: var(--text);
    font-family: var(--font-ui);
    font-size: 15px;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* scanline overlay */
  body::after {
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent, transparent 2px,
      rgba(0,0,0,.08) 2px, rgba(0,0,0,.08) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  /* grid noise texture */
  body::before {
    content: '';
    position: fixed; inset: 0;
    background-image:
      radial-gradient(ellipse 80% 50% at 10% 0%, rgba(0,100,200,.12) 0%, transparent 70%),
      radial-gradient(ellipse 60% 40% at 90% 100%, rgba(0,200,120,.07) 0%, transparent 70%);
    pointer-events: none;
    z-index: 0;
  }

  /* ── Header ── */
  header {
    position: sticky; top: 0; z-index: 100;
    background: rgba(3,5,10,.92);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 2rem;
    height: 60px;
  }

  .logo {
    font-family: var(--font-hd);
    font-size: 1.2rem;
    font-weight: 900;
    letter-spacing: .15em;
    color: var(--accent);
    text-shadow: var(--glow);
    display: flex; align-items: center; gap: .75rem;
  }

  .logo-icon {
    width: 28px; height: 28px;
    border: 2px solid var(--accent);
    border-radius: 4px;
    display: flex; align-items: center; justify-content: center;
    font-size: .9rem;
    box-shadow: var(--glow), inset 0 0 8px rgba(0,212,255,.15);
    animation: pulse-border 2s ease-in-out infinite;
  }

  @keyframes pulse-border {
    0%,100% { box-shadow: var(--glow), inset 0 0 8px rgba(0,212,255,.15); }
    50%      { box-shadow: 0 0 20px rgba(0,212,255,.6), inset 0 0 12px rgba(0,212,255,.3); }
  }

  .header-right {
    display: flex; align-items: center; gap: 1.5rem;
    font-family: var(--font-mono);
    font-size: .75rem;
    color: var(--textdim);
  }

  #clock { color: var(--accent2); }

  .conn-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--muted);
    transition: background .3s, box-shadow .3s;
  }
  .conn-dot.live {
    background: var(--accent2);
    box-shadow: 0 0 8px var(--accent2);
    animation: blink 1.4s ease-in-out infinite;
  }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.4} }

  /* ── Layout ── */
  main {
    position: relative; z-index: 1;
    display: grid;
    grid-template-columns: 280px 1fr;
    grid-template-rows: auto 1fr;
    gap: 1px;
    height: calc(100vh - 60px);
    background: var(--border);
  }

  .sidebar {
    grid-row: 1 / 3;
    background: var(--bg1);
    display: flex; flex-direction: column;
    overflow-y: auto;
  }

  .top-bar {
    background: var(--bg1);
    padding: 1rem 1.25rem;
    display: flex; gap: 1rem; flex-wrap: wrap;
  }

  .feed-panel {
    background: var(--bg0);
    overflow-y: auto;
    display: flex; flex-direction: column;
  }

  /* ── Stat cards ── */
  .stat-card {
    flex: 1; min-width: 120px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: .75rem 1rem;
    position: relative;
    overflow: hidden;
  }
  .stat-card::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent);
  }
  .stat-card.high::before  { background: var(--danger); }
  .stat-card.crit::before  { background: var(--critical); }
  .stat-card.warn::before  { background: var(--warn); }

  .stat-label {
    font-family: var(--font-mono);
    font-size: .65rem;
    letter-spacing: .12em;
    color: var(--textdim);
    text-transform: uppercase;
    margin-bottom: .3rem;
  }
  .stat-value {
    font-family: var(--font-hd);
    font-size: 1.8rem;
    font-weight: 700;
    line-height: 1;
    color: var(--text);
  }
  .stat-card.high  .stat-value { color: var(--danger); }
  .stat-card.crit  .stat-value { color: var(--critical); }

  /* ── Sidebar sections ── */
  .sidebar-section {
    border-bottom: 1px solid var(--border);
    padding: 1rem 1.25rem;
  }
  .sidebar-title {
    font-family: var(--font-mono);
    font-size: .65rem;
    letter-spacing: .15em;
    color: var(--accent);
    text-transform: uppercase;
    margin-bottom: .85rem;
    display: flex; align-items: center; gap: .5rem;
  }
  .sidebar-title::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }

  /* bar chart rows */
  .bar-row {
    display: flex; align-items: center; gap: .6rem;
    margin-bottom: .5rem;
    font-size: .82rem;
  }
  .bar-label {
    font-family: var(--font-mono);
    font-size: .72rem;
    color: var(--textdim);
    width: 110px;
    flex-shrink: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .bar-track {
    flex: 1;
    height: 6px;
    background: var(--bg3);
    border-radius: 3px;
    overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    border-radius: 3px;
    background: var(--accent);
    transition: width .5s ease;
  }
  .bar-count {
    font-family: var(--font-mono);
    font-size: .7rem;
    color: var(--text);
    min-width: 28px;
    text-align: right;
  }

  /* level-specific bar colours */
  .bar-INFO     { background: var(--muted); }
  .bar-LOW      { background: var(--accent2); }
  .bar-MEDIUM   { background: var(--warn); }
  .bar-HIGH     { background: var(--danger); }
  .bar-CRITICAL { background: var(--critical); }

  /* agent cards */
  .agent-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: .7rem .9rem;
    margin-bottom: .6rem;
    display: flex; align-items: center; gap: .75rem;
  }
  .agent-indicator {
    width: 9px; height: 9px; border-radius: 50%;
    background: var(--muted); flex-shrink: 0;
  }
  .agent-indicator.online {
    background: var(--accent2);
    box-shadow: 0 0 7px var(--accent2);
    animation: blink 2s ease-in-out infinite;
  }
  .agent-info { flex: 1; min-width: 0; }
  .agent-hostname {
    font-family: var(--font-mono);
    font-size: .8rem;
    color: var(--text);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .agent-meta {
    font-size: .7rem;
    color: var(--textdim);
    margin-top: .15rem;
  }
  .agent-count {
    font-family: var(--font-hd);
    font-size: .9rem;
    font-weight: 700;
    color: var(--accent);
  }

  /* ── Alert feed ── */
  .feed-header {
    position: sticky; top: 0; z-index: 10;
    background: rgba(3,5,10,.95);
    backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--border);
    padding: .75rem 1.25rem;
    display: flex; align-items: center; justify-content: space-between;
  }
  .feed-title {
    font-family: var(--font-hd);
    font-size: .9rem;
    letter-spacing: .1em;
    color: var(--accent);
  }
  .feed-controls { display: flex; gap: .75rem; align-items: center; }

  .filter-btn {
    font-family: var(--font-mono);
    font-size: .68rem;
    letter-spacing: .08em;
    padding: .25rem .6rem;
    border: 1px solid var(--border);
    border-radius: 3px;
    background: transparent;
    color: var(--textdim);
    cursor: pointer;
    transition: all .2s;
  }
  .filter-btn:hover, .filter-btn.active {
    border-color: var(--accent);
    color: var(--accent);
    background: rgba(0,212,255,.08);
  }
  .filter-btn.CRITICAL.active { border-color:var(--critical); color:var(--critical); background:rgba(255,0,170,.08); }
  .filter-btn.HIGH.active     { border-color:var(--danger);   color:var(--danger);   background:rgba(255,60,90,.08); }
  .filter-btn.MEDIUM.active   { border-color:var(--warn);     color:var(--warn);     background:rgba(255,204,0,.08); }

  #alert-list {
    flex: 1;
    padding: .75rem 1rem;
    display: flex;
    flex-direction: column;
    gap: .45rem;
  }

  /* alert row */
  .alert-row {
    display: grid;
    grid-template-columns: auto 90px 130px 1fr auto;
    gap: .6rem;
    align-items: center;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-left: 3px solid var(--muted);
    border-radius: 5px;
    padding: .55rem .85rem;
    font-size: .82rem;
    animation: row-in .25s ease;
    transition: border-color .2s, background .2s;
  }
  .alert-row:hover {
    background: var(--bg3);
    border-color: var(--accent);
    border-left-color: inherit;
  }

  @keyframes row-in {
    from { opacity:0; transform:translateY(-6px); }
    to   { opacity:1; transform:translateY(0); }
  }

  .alert-row.INFO     { border-left-color: var(--muted); }
  .alert-row.LOW      { border-left-color: var(--accent2); }
  .alert-row.MEDIUM   { border-left-color: var(--warn); }
  .alert-row.HIGH     { border-left-color: var(--danger); }
  .alert-row.CRITICAL { border-left-color: var(--critical); background: rgba(255,0,170,.05); }

  .alert-level {
    font-family: var(--font-mono);
    font-size: .65rem;
    letter-spacing: .08em;
    padding: .2rem .45rem;
    border-radius: 3px;
    font-weight: 700;
    white-space: nowrap;
  }
  .alert-level.INFO     { color: var(--textdim);  background: rgba(58,84,112,.3); }
  .alert-level.LOW      { color: var(--accent2);  background: rgba(0,255,157,.1); }
  .alert-level.MEDIUM   { color: var(--warn);     background: rgba(255,204,0,.1); }
  .alert-level.HIGH     { color: var(--danger);   background: rgba(255,60,90,.12); }
  .alert-level.CRITICAL { color: var(--critical); background: rgba(255,0,170,.15); }

  .alert-ts {
    font-family: var(--font-mono);
    font-size: .7rem;
    color: var(--textdim);
    white-space: nowrap;
  }
  .alert-category {
    font-family: var(--font-mono);
    font-size: .75rem;
    color: var(--accent);
    white-space: nowrap;
  }
  .alert-message {
    color: var(--text);
    font-size: .82rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .alert-agent {
    font-family: var(--font-mono);
    font-size: .65rem;
    color: var(--textdim);
    text-align: right;
    white-space: nowrap;
  }

  .empty-state {
    flex: 1;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    gap: 1rem;
    color: var(--textdim);
    font-family: var(--font-mono);
    font-size: .85rem;
    letter-spacing: .05em;
    padding: 4rem;
  }
  .empty-icon { font-size: 2.5rem; opacity: .3; }
  .empty-state p { text-align: center; line-height: 1.7; }

  /* scrollbar */
  ::-webkit-scrollbar { width: 5px; }
  ::-webkit-scrollbar-track { background: var(--bg0); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--muted); }

  /* toasts */
  #toast-container {
    position: fixed; bottom: 1.5rem; right: 1.5rem;
    z-index: 1000;
    display: flex; flex-direction: column; gap: .5rem;
    pointer-events: none;
  }
  .toast {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 5px;
    padding: .6rem 1rem;
    font-family: var(--font-mono);
    font-size: .75rem;
    color: var(--text);
    max-width: 340px;
    animation: toast-in .25s ease, toast-out .3s ease 2.7s forwards;
    pointer-events: none;
  }
  .toast.CRITICAL { border-left-color: var(--critical); }
  .toast.HIGH     { border-left-color: var(--danger); }
  .toast.MEDIUM   { border-left-color: var(--warn); }
  @keyframes toast-in  { from{opacity:0;transform:translateX(20px)} to{opacity:1;transform:none} }
  @keyframes toast-out { from{opacity:1} to{opacity:0;transform:translateX(20px)} }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">⬡</div>
    NETSENTINEL
  </div>
  <div class="header-right">
    <div class="conn-dot" id="conn-dot"></div>
    <span id="conn-label">OFFLINE</span>
    <span>|</span>
    <span id="clock">--:--:--</span>
  </div>
</header>

<main>
  <!-- SIDEBAR -->
  <aside class="sidebar">
    <!-- counters -->
    <div class="sidebar-section">
      <div class="sidebar-title">Threat Overview</div>
      <div style="display:flex; flex-direction:column; gap:.6rem;">
        <div class="stat-card">
          <div class="stat-label">Total Alerts</div>
          <div class="stat-value" id="stat-total">0</div>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:.6rem;">
          <div class="stat-card high">
            <div class="stat-label">HIGH</div>
            <div class="stat-value" id="stat-high">0</div>
          </div>
          <div class="stat-card crit">
            <div class="stat-label">CRITICAL</div>
            <div class="stat-value" id="stat-crit">0</div>
          </div>
        </div>
      </div>
    </div>

    <!-- by category -->
    <div class="sidebar-section" style="flex:0 0 auto">
      <div class="sidebar-title">By Category</div>
      <div id="cat-bars"></div>
    </div>

    <!-- by level -->
    <div class="sidebar-section" style="flex:0 0 auto">
      <div class="sidebar-title">By Severity</div>
      <div id="level-bars"></div>
    </div>

    <!-- agents -->
    <div class="sidebar-section" style="flex:1">
      <div class="sidebar-title">Agents</div>
      <div id="agent-list">
        <div style="font-family:var(--font-mono);font-size:.72rem;color:var(--textdim);">
          Awaiting agent connections…
        </div>
      </div>
    </div>
  </aside>

  <!-- TOP BAR -->
  <div class="top-bar">
    <div class="stat-card" style="flex:0 0 auto; min-width:140px;">
      <div class="stat-label">Alerts / min</div>
      <div class="stat-value" id="stat-rate">0.0</div>
    </div>
    <div style="flex:1; display:flex; align-items:center; justify-content:flex-end; gap:.5rem; flex-wrap:wrap;">
      <span style="font-family:var(--font-mono);font-size:.68rem;color:var(--textdim);margin-right:.3rem;">FILTER:</span>
      <button class="filter-btn active" data-level="ALL">ALL</button>
      <button class="filter-btn CRITICAL" data-level="CRITICAL">☠ CRITICAL</button>
      <button class="filter-btn HIGH"     data-level="HIGH">⚠ HIGH</button>
      <button class="filter-btn MEDIUM"   data-level="MEDIUM">▲ MEDIUM</button>
      <button class="filter-btn"          data-level="LOW">● LOW</button>
      <button class="filter-btn"          data-level="INFO">ℹ INFO</button>
    </div>
  </div>

  <!-- FEED -->
  <div class="feed-panel">
    <div class="feed-header">
      <span class="feed-title">⬡ LIVE ALERT FEED</span>
      <span id="feed-count" style="font-family:var(--font-mono);font-size:.72rem;color:var(--textdim);">0 events</span>
    </div>
    <div id="alert-list">
      <div class="empty-state" id="empty-state">
        <div class="empty-icon">◈</div>
        <p>No alerts yet.<br/>Start agents on monitored hosts<br/>and threats will appear here in real time.</p>
      </div>
    </div>
  </div>
</main>

<div id="toast-container"></div>

<script>
const socket = io({ secure: true, rejectUnauthorized: false });

let allAlerts   = [];
let activeFilter = 'ALL';
let rateWindow  = [];

// ── connection ──────────────────────────────────────────────────────────────
socket.on('connect', () => {
  document.getElementById('conn-dot').classList.add('live');
  document.getElementById('conn-label').textContent = 'LIVE';
  fetchState();
});
socket.on('disconnect', () => {
  document.getElementById('conn-dot').classList.remove('live');
  document.getElementById('conn-label').textContent = 'OFFLINE';
});

// ── real-time events ────────────────────────────────────────────────────────
socket.on('alert', alert => {
  allAlerts.unshift(alert);
  rateWindow.push(Date.now());
  renderFeed();
  if (shouldToast(alert.level)) showToast(alert);
});
socket.on('stats',  updateStats);
socket.on('agents', updateAgents);

// ── initial state ────────────────────────────────────────────────────────────
async function fetchState() {
  try {
    const r = await fetch('/api/state', {
      headers: { 'X-API-Key': window._SENTINEL_KEY || '' }
    });
    if (!r.ok) return;
    const d = await r.json();
    allAlerts = d.alerts || [];
    renderFeed();
    updateStats(d.stats);
    updateAgents(d.agents);
  } catch(e) {}
}

// ── filters ──────────────────────────────────────────────────────────────────
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.level;
    renderFeed();
  });
});

function filteredAlerts() {
  if (activeFilter === 'ALL') return allAlerts;
  return allAlerts.filter(a => a.level === activeFilter);
}

// ── render feed ──────────────────────────────────────────────────────────────
function renderFeed() {
  const list   = document.getElementById('alert-list');
  const empty  = document.getElementById('empty-state');
  const alerts = filteredAlerts().slice(0, 400);

  document.getElementById('feed-count').textContent = `${alerts.length} events`;

  if (alerts.length === 0) {
    if (!empty) {
      list.innerHTML = `<div class="empty-state" id="empty-state">
        <div class="empty-icon">◈</div>
        <p>No alerts match the current filter.</p></div>`;
    }
    return;
  }

  // Re-render top portion only to avoid thrash
  const rows = alerts.map(a => `
    <div class="alert-row ${a.level}">
      <span class="alert-level ${a.level}">${a.level}</span>
      <span class="alert-ts">${fmtTime(a.ts)}</span>
      <span class="alert-category">${a.category}</span>
      <span class="alert-message" title="${escHtml(a.message)}">${escHtml(a.message)}</span>
      <span class="alert-agent">${escHtml(a.hostname)}</span>
    </div>`).join('');

  list.innerHTML = rows;
}

// ── stats ────────────────────────────────────────────────────────────────────
function updateStats(stats) {
  if (!stats) return;
  set('stat-total', stats.total || 0);
  set('stat-high',  (stats.by_level || {})['HIGH']     || 0);
  set('stat-crit',  (stats.by_level || {})['CRITICAL'] || 0);

  // Category bars
  const catEl = document.getElementById('cat-bars');
  const cats  = Object.entries(stats.by_category || {}).sort((a,b) => b[1]-a[1]).slice(0, 12);
  const maxC  = cats[0]?.[1] || 1;
  catEl.innerHTML = cats.map(([k,v]) => barRow(k, v, maxC)).join('');

  // Level bars
  const lvlEl  = document.getElementById('level-bars');
  const levels = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  const maxL   = Math.max(...levels.map(l => (stats.by_level||{})[l]||0), 1);
  lvlEl.innerHTML = levels.map(l =>
    barRow(l, (stats.by_level||{})[l]||0, maxL, `bar-fill ${l}`)
  ).join('');
}

function barRow(label, val, max, cls='bar-fill') {
  const pct = max > 0 ? Math.round(val/max*100) : 0;
  return `<div class="bar-row">
    <span class="bar-label">${escHtml(label)}</span>
    <div class="bar-track"><div class="${cls}" style="width:${pct}%"></div></div>
    <span class="bar-count">${val}</span>
  </div>`;
}

// ── agents ───────────────────────────────────────────────────────────────────
function updateAgents(agents) {
  if (!agents) return;
  const el = document.getElementById('agent-list');
  if (!agents.length) {
    el.innerHTML = `<div style="font-family:var(--font-mono);font-size:.72rem;color:var(--textdim);">Awaiting agent connections…</div>`;
    return;
  }
  el.innerHTML = agents.map(a => `
    <div class="agent-card">
      <div class="agent-indicator ${a.online ? 'online' : ''}"></div>
      <div class="agent-info">
        <div class="agent-hostname">${escHtml(a.hostname)}</div>
        <div class="agent-meta">${escHtml(a.ip||'')} · ${a.online?'online':'offline'}</div>
      </div>
      <div class="agent-count">${a.alert_count}</div>
    </div>`).join('');
}

// ── toasts ───────────────────────────────────────────────────────────────────
function shouldToast(level) {
  return ['HIGH','CRITICAL'].includes(level);
}
function showToast(alert) {
  const tc  = document.getElementById('toast-container');
  const div = document.createElement('div');
  div.className = `toast ${alert.level}`;
  div.textContent = `[${alert.level}] ${alert.category} — ${alert.message.slice(0,80)}`;
  tc.appendChild(div);
  setTimeout(() => div.remove(), 3200);
}

// ── rate calculator ───────────────────────────────────────────────────────────
setInterval(() => {
  const now  = Date.now();
  const min  = now - 60000;
  rateWindow = rateWindow.filter(t => t > min);
  set('stat-rate', rateWindow.length.toFixed(1));
}, 2000);

// ── clock ────────────────────────────────────────────────────────────────────
function tickClock() {
  document.getElementById('clock').textContent =
    new Date().toTimeString().slice(0,8);
}
setInterval(tickClock, 1000);
tickClock();

// ── utils ────────────────────────────────────────────────────────────────────
function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function fmtTime(iso) {
  try { return new Date(iso).toTimeString().slice(0,8); } catch{return iso;}
}
function escHtml(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>"""


@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Server")
    parser.add_argument("--config", default="sentinel_config.json")
    args = parser.parse_args()

    cfg = load_config(args.config)
    app.config["API_KEY"] = cfg["api_key"]

    host = cfg.get("server_host", "0.0.0.0")
    port = cfg.get("server_port", 8443)

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(cfg["server_cert"], cfg["server_key"])
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_ctx.set_ciphers(
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    )

    print(f"""
  ███╗   ██╗███████╗████████╗
  ████╗  ██║██╔════╝╚══██╔══╝
  ██╔██╗ ██║█████╗     ██║   
  ██║╚██╗██║██╔══╝     ██║   
  ██║ ╚████║███████╗   ██║   
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   SENTINEL SERVER

  Dashboard   → https://{host}:{port}/
  Alert API   → https://{host}:{port}/api/alert
  TLS         → TLS 1.2+ (ECDHE / AES-GCM)
  Auth        → X-API-Key (shared secret)
""")

    try:
        import gevent.pywsgi
        from geventwebsocket.handler import WebSocketHandler
        server = gevent.pywsgi.WSGIServer(
            (host, port), app,
            handler_class=WebSocketHandler,
            ssl_context=ssl_ctx,
        )
        print(f"  [*] Listening on {host}:{port}  (gevent/TLS)  Ctrl-C to stop\n")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  [!] Server stopped.")


if __name__ == "__main__":
    main()
