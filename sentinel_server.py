#!/usr/bin/env python3
"""sentinel_server.py — NetSentinel Central Command Server (v4)
Multi-tab GUI: Overview / Live Feed / Agents / Analytics | TLS + API-key auth
pip install flask flask-socketio gevent gevent-websocket cryptography
"""
import argparse, json, ssl, threading, time, uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
try:
    from flask import Flask, request, jsonify, render_template_string
    from flask_socketio import SocketIO
except ImportError:
    raise SystemExit("[!] pip install flask flask-socketio gevent gevent-websocket")

# ── constants ─────────────────────────────────────────────────────────────────
MAX_AGENTS        = 500          # SEC-04: cap registered agents
AGENT_TTL_SEC     = 86400        # SEC-04: prune agents unseen for 24 h
RATE_LIMIT_WINDOW = 5            # seconds  SEC-03
RATE_LIMIT_MAX    = 50           # alerts per agent per window  SEC-03
VALID_LEVELS      = frozenset({"INFO","LOW","MEDIUM","HIGH","CRITICAL"})  # SEC-01
MAX_FIELD_LEN     = 2048         # SEC-02
MAX_MSG_LEN       = 4096         # SEC-02
# ── per-agent rate buckets ─────────────────────────────────────────────────────
from collections import defaultdict as _dd2
_rate_buckets = _dd2(lambda: {"count":0,"window_start":0.0})
_rate_lock = threading.Lock()

def load_config(path):
    p=Path(path)
    if not p.exists(): raise SystemExit(f"[!] Config not found: {path}")
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError as e:
        raise SystemExit(f"[!] Config JSON error in {path}: {e}")

MAX_ALERTS=5000; alerts_store=deque(maxlen=MAX_ALERTS); alerts_lock=threading.Lock()
TBUCKETS=60; timeline=deque([0]*TBUCKETS,maxlen=TBUCKETS); tl_lock=threading.Lock()
tl_last_min=int(time.time()//60); agents={}; agents_lock=threading.Lock()
category_counts=defaultdict(int); level_counts=defaultdict(int); src_counts=defaultdict(int)

app=Flask(__name__); app.config["SECRET_KEY"]=uuid.uuid4().hex
socketio=SocketIO(app,async_mode="gevent",cors_allowed_origins=[],logger=False,engineio_logger=False)

# ── helpers ───────────────────────────────────────────────────────────────────
def _trunc(s, n=MAX_FIELD_LEN):
    return str(s or "")[:n]

def _rate_ok(agent_id):
    now = time.time()
    with _rate_lock:
        b = _rate_buckets[agent_id]
        if now - b["window_start"] > RATE_LIMIT_WINDOW:
            b["count"] = 0; b["window_start"] = now
        b["count"] += 1
        return b["count"] <= RATE_LIMIT_MAX

def _prune_agents():
    cutoff = time.time() - AGENT_TTL_SEC
    with agents_lock:
        stale = [aid for aid, info in agents.items()
                 if datetime.fromisoformat(info.get("last_seen","1970-01-01T00:00:00+00:00")).timestamp() < cutoff]
        for aid in stale:
            del agents[aid]

def _periodic_prune():
    while True:
        time.sleep(3600)
        _prune_agents()

def require_api_key(f):
    @wraps(f)
    def w(*a,**k):
        if request.headers.get("X-API-Key","")!=app.config["API_KEY"]: return jsonify({"error":"Unauthorized"}),401
        return f(*a,**k)
    return w

def _tick():
    global tl_last_min
    nm=int(time.time()//60)
    with tl_lock:
        for _ in range(min(nm-tl_last_min,TBUCKETS)): timeline.append(0)
        tl_last_min=nm; timeline[-1]+=1

def _stats():
    with alerts_lock:
        return {"total":sum(level_counts.values()),"by_level":dict(level_counts),
            "by_category":dict(sorted(category_counts.items(),key=lambda x:-x[1])[:20]),
            "top_sources":dict(sorted(src_counts.items(),key=lambda x:-x[1])[:10])}

def _agents():
    now=time.time(); result=[]
    with agents_lock:
        for aid,info in agents.items():
            try: online=(now-datetime.fromisoformat(info["last_seen"]).timestamp())<90
            except: online=False
            result.append({**info,"agent_id":aid,"online":online})
    result.sort(key=lambda a:a.get("alert_count",0),reverse=True); return result

def _tl():
    with tl_lock: return list(timeline)

@socketio.on("connect")
def on_connect(auth=None):
    token = (auth or {}).get("token","") if isinstance(auth,dict) else ""
    if token != app.config["API_KEY"]:
        from flask_socketio import disconnect as _dc; _dc(); return False

@app.route("/api/alert",methods=["POST"])
@require_api_key
def recv():
    data=request.get_json(silent=True)
    if not data: return jsonify({"error":"Bad request"}),400
    if not {"level","category","message","agent_id","hostname"}.issubset(data): return jsonify({"error":"Missing fields"}),400
    # SEC-01: validate level
    level=str(data.get("level","")).upper()
    if level not in VALID_LEVELS: return jsonify({"error":"Invalid level"}),422
    # SEC-02: truncate all string fields
    agent_id=_trunc(data["agent_id"],64); hostname=_trunc(data["hostname"],253)
    category=_trunc(data["category"]); message=_trunc(data["message"],MAX_MSG_LEN)
    src=_trunc(data.get("src","")); os_tag=_trunc(data.get("os",""),128)
    # SEC-03: rate limit per agent
    if not _rate_ok(agent_id): return jsonify({"error":"Rate limit exceeded"}),429
    alert={"id":uuid.uuid4().hex[:12],"ts":datetime.now(timezone.utc).isoformat(),"level":level,
        "category":category,"message":message,"src":src,"agent_id":agent_id,"hostname":hostname}
    with alerts_lock:
        alerts_store.appendleft(alert); category_counts[category]+=1; level_counts[level]+=1
        if src: src_counts[src]+=1
    _tick(); ip=request.remote_addr
    with agents_lock:
        if agent_id not in agents:
            # SEC-04: enforce agent cap
            if len(agents)>=MAX_AGENTS: return jsonify({"error":"Agent limit reached"}),429
            agents[agent_id]={"hostname":hostname,"first_seen":alert["ts"],"alert_count":0,"ip":ip,"os":os_tag}
        agents[agent_id]["last_seen"]=alert["ts"]; agents[agent_id]["alert_count"]+=1; agents[agent_id]["ip"]=ip
        if os_tag: agents[agent_id]["os"]=os_tag
    socketio.emit("alert",alert); socketio.emit("stats",_stats()); socketio.emit("timeline",_tl())
    return jsonify({"ok":True,"id":alert["id"]}),201

@app.route("/api/agent/heartbeat",methods=["POST"])
@require_api_key
def hb():
    data=request.get_json(silent=True) or {}
    aid=_trunc(data.get("agent_id",""),64)
    if not aid: return jsonify({"error":"Missing agent_id"}),400
    hostname=_trunc(data.get("hostname","unknown"),253); os_tag=_trunc(data.get("os",""),128)
    now_iso=datetime.now(timezone.utc).isoformat()
    with agents_lock:
        if aid not in agents:
            if len(agents)>=MAX_AGENTS: return jsonify({"ok":True}),200
            agents[aid]={"hostname":hostname,"first_seen":now_iso,"alert_count":0,"ip":request.remote_addr,"os":os_tag}
        agents[aid]["last_seen"]=now_iso; agents[aid]["ip"]=request.remote_addr
        if os_tag: agents[aid]["os"]=os_tag
        if hostname and hostname!="unknown": agents[aid]["hostname"]=hostname
    socketio.emit("agents",_agents()); return jsonify({"ok":True}),200

@app.route("/api/state",methods=["GET"])
@require_api_key
def state():
    with alerts_lock: recent=list(alerts_store)[:500]
    return jsonify({"alerts":recent,"stats":_stats(),"agents":_agents(),"timeline":_tl()})

@app.route("/api/alerts/export",methods=["GET"])
@require_api_key
def export():
    # BUG-02 fix: return proper Response so fetch() can handle it with auth headers
    from flask import Response as _R
    with alerts_lock: data=list(alerts_store)
    return _R(json.dumps(data,indent=2),mimetype="application/json",
        headers={"Content-Disposition":"attachment; filename=netsentinel-alerts.json"})

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>NetSentinel — Command Center</title>
<link href="https://fonts.googleapis.com/css2?family=VT323&family=Courier+Prime:wght@400;700&family=Bebas+Neue&display=swap" rel="stylesheet"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.6.1/socket.io.min.js"></script>
<style>
:root{
  --bg:#050800;--bg1:#080d02;--bg2:#0c1204;--bg3:#111a06;
  --amber:#ffb000;--amber2:#ffd060;--amber-dim:#7a5500;
  --green:#39ff14;--red:#ff2020;--orange:#ff7700;
  --border:#1e2e08;--border2:#3d5518;
  --text:#d4a800;--textdim:#7a6000;--textfaint:#3a2e00;
  --critical:#ff0055;--high:#ff4400;--medium:#ffaa00;--low:#88cc00;--info:#00aacc;
  --fm:'Courier Prime','Courier New',monospace;
  --fh:'Bebas Neue',sans-serif;--fc:'VT323',monospace;
  --ga:0 0 8px rgba(255,176,0,.5),0 0 20px rgba(255,176,0,.2);
  --gg:0 0 8px rgba(57,255,20,.4);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--text);font-family:var(--fm);font-size:13px;line-height:1.5;
  background-image:repeating-linear-gradient(0deg,transparent 0,transparent 3px,rgba(0,0,0,.07) 3px,rgba(0,0,0,.07) 4px),
    radial-gradient(ellipse 70% 60% at 50% 40%,rgba(60,80,0,.1) 0%,transparent 80%);}
@keyframes flicker{0%,100%{opacity:1}93%{opacity:.96}96%{opacity:.97}}
body{animation:flicker 8s infinite}
#app{display:grid;grid-template-rows:52px 40px 1fr;height:100vh;overflow:hidden}
header{display:flex;align-items:center;justify-content:space-between;padding:0 20px;border-bottom:2px solid var(--border2);background:var(--bg1);position:relative;}
header::after{content:'';position:absolute;bottom:-4px;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--amber),transparent);opacity:.4;}
.logo{font-family:var(--fh);font-size:1.9rem;letter-spacing:.3em;color:var(--amber);text-shadow:var(--ga);display:flex;align-items:center;gap:12px;}
@keyframes spin-slow{to{transform:rotate(360deg)}}
.logo-hex{font-size:1.9rem;text-shadow:var(--ga);animation:spin-slow 25s linear infinite}
.hm{display:flex;align-items:center;gap:18px;font-family:var(--fc);font-size:.95rem;color:var(--textdim)}
.hm span{border-left:1px solid var(--border2);padding-left:16px}
.hm span:first-child{border:none;padding:0}
#clock{color:var(--amber);font-size:1.05rem}
#cst{transition:color .3s}
#cst.live{color:var(--green);text-shadow:var(--gg)}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
.bl{animation:blink .9s step-end infinite}
nav{display:flex;align-items:stretch;border-bottom:1px solid var(--border2);background:var(--bg1);padding:0 18px;gap:2px;}
.tab{font-family:var(--fc);font-size:1rem;letter-spacing:.12em;color:var(--textdim);padding:0 16px;cursor:pointer;border:none;background:transparent;border-bottom:3px solid transparent;transition:all .15s;display:flex;align-items:center;gap:7px;position:relative;top:1px;}
.tab:hover{color:var(--amber2)}.tab.active{color:var(--amber);border-bottom-color:var(--amber);text-shadow:var(--ga);background:rgba(255,176,0,.04)}
.bdg{font-family:var(--fm);font-size:.6rem;background:var(--critical);color:#fff;border-radius:2px;padding:1px 5px;display:none}
.bdg.on{display:inline-block}
.panel{display:none;overflow:hidden;height:100%}.panel.active{display:grid}
/* OVERVIEW */
#po{grid-template-columns:270px 1fr 250px;grid-template-rows:1fr 1fr;gap:1px;background:var(--border)}
.card{background:var(--bg1);overflow:hidden;display:flex;flex-direction:column}
.ch{font-family:var(--fc);font-size:.87rem;letter-spacing:.14em;color:var(--amber-dim);padding:7px 13px;border-bottom:1px solid var(--border);flex-shrink:0;display:flex;align-items:center;justify-content:space-between;}
.ch::before{content:'▸ ';color:var(--amber)}
.cb{flex:1;overflow:hidden;padding:13px;display:flex;flex-direction:column}
#gc{grid-row:1/3;align-items:center;justify-content:center}
#gc .cb{align-items:center;justify-content:center;gap:13px}
.gr{position:relative;width:185px;height:185px}.gr svg{transform:rotate(-90deg)}
.gbg{fill:none;stroke:var(--bg3);stroke-width:14}
.garc{fill:none;stroke-width:14;stroke-linecap:round;transition:stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1),stroke .5s}
.gl{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.glvl{font-family:var(--fh);font-size:2.1rem;letter-spacing:.1em;line-height:1}
.gsub{font-family:var(--fc);font-size:.73rem;letter-spacing:.14em;color:var(--textdim);margin-top:4px}
.sr{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;width:100%}
.ms{background:var(--bg2);border:1px solid var(--border);border-top:2px solid var(--border2);padding:7px 7px;text-align:center}
.msv{font-family:var(--fh);font-size:1.45rem;line-height:1;color:var(--amber)}
.msv.c{color:var(--critical)}.msv.h{color:var(--high)}.msv.m{color:var(--medium)}.msv.l{color:var(--low)}
.msl{font-family:var(--fc);font-size:.68rem;color:var(--textdim);letter-spacing:.07em;margin-top:2px}
#tlc{grid-column:2}#spark-svg{width:100%;flex:1}
#catc{grid-column:2}
.br{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.bl2{font-family:var(--fc);font-size:.77rem;color:var(--textdim);width:148px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bt{flex:1;height:7px;background:var(--bg3);border:1px solid var(--border);overflow:hidden}
.bf{height:100%;background:var(--amber-dim);transition:width .6s}
.bc{font-family:var(--fc);font-size:.77rem;color:var(--amber);min-width:32px;text-align:right}
#critc{grid-column:3;grid-row:1/3}
#clist{flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:5px}
.ci{background:var(--bg2);border-left:3px solid var(--critical);padding:6px 10px}
@keyframes si{from{opacity:0;transform:translateX(6px)}to{opacity:1;transform:none}}
.ci{animation:si .2s ease}
.cic{color:var(--critical);font-size:.67rem;letter-spacing:.07em}
.cim{color:var(--text);font-size:.71rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}
.cix{color:var(--textdim);font-size:.64rem;margin-top:2px}
/* FEED */
#pf{grid-template-rows:auto 1fr}
.ftb{display:flex;align-items:center;gap:8px;padding:7px 12px;border-bottom:1px solid var(--border);background:var(--bg1);flex-wrap:wrap;}
.fc2{font-family:var(--fc);font-size:.87rem;letter-spacing:.06em;padding:2px 9px;border:1px solid var(--border2);background:transparent;color:var(--textdim);cursor:pointer;transition:all .15s;}
.fc2:hover{color:var(--amber);border-color:var(--amber-dim)}
.fc2.active{color:var(--amber);border-color:var(--amber);background:rgba(255,176,0,.07);text-shadow:var(--ga)}
.fc2.active.CRITICAL{color:var(--critical);border-color:var(--critical);background:rgba(255,0,85,.07)}
.fc2.active.HIGH{color:var(--high);border-color:var(--high);background:rgba(255,68,0,.07)}
.fc2.active.MEDIUM{color:var(--medium);border-color:var(--medium);background:rgba(255,170,0,.07)}
.sb{font-family:var(--fm);font-size:.77rem;background:var(--bg2);border:1px solid var(--border2);color:var(--amber);padding:2px 9px;outline:none;width:190px;margin-left:auto;}
.sb::placeholder{color:var(--textfaint)}.sb:focus{border-color:var(--amber-dim)}
.fcnt{font-family:var(--fc);font-size:.8rem;color:var(--textdim);white-space:nowrap}
#fs{overflow-y:auto;padding:6px;display:flex;flex-direction:column;gap:2px}
.ar{display:grid;grid-template-columns:74px 64px 140px 1fr 115px;gap:7px;align-items:center;padding:5px 9px;border:1px solid var(--border);border-left:4px solid transparent;background:var(--bg2);cursor:pointer;transition:background .1s;}
@keyframes rin{from{opacity:0;transform:translateY(-3px)}to{opacity:1;transform:none}}
.ar{animation:rin .2s ease}.ar:hover{background:var(--bg3)}
.ar.CRITICAL{border-left-color:var(--critical);background:rgba(255,0,85,.05)}
.ar.HIGH{border-left-color:var(--high)}.ar.MEDIUM{border-left-color:var(--medium)}
.ar.LOW{border-left-color:var(--low)}.ar.INFO{border-left-color:var(--info)}
.lb{font-family:var(--fc);font-size:.72rem;letter-spacing:.05em;padding:1px 5px;font-weight:700}
.lb.CRITICAL{color:var(--critical);border:1px solid var(--critical)}.lb.HIGH{color:var(--high);border:1px solid var(--high)}
.lb.MEDIUM{color:var(--medium);border:1px solid var(--medium)}.lb.LOW{color:var(--low);border:1px solid var(--low)}
.lb.INFO{color:var(--info);border:1px solid var(--info)}
.ats{font-family:var(--fc);font-size:.77rem;color:var(--textdim)}
.acat{font-family:var(--fc);font-size:.79rem;color:var(--amber);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.amsg{font-size:.75rem;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ahost{font-family:var(--fc);font-size:.71rem;color:var(--textdim);text-align:right;white-space:nowrap}
.adet{display:none;background:var(--bg3);border:1px solid var(--border2);border-top:none;padding:9px 13px;font-size:.76rem;color:var(--text);line-height:1.7;margin-bottom:2px;}
.adet.open{display:block}
.dkv{display:grid;grid-template-columns:96px 1fr;column-gap:8px}
.dk{color:var(--textdim)}.dv{color:var(--amber2);font-family:var(--fc);font-size:.8rem}
/* AGENTS */
#pag{grid-template-rows:auto 1fr}
.agh{background:var(--bg1);padding:8px 13px;font-family:var(--fc);font-size:.87rem;color:var(--textdim);border-bottom:1px solid var(--border2);}
#agrid{overflow-y:auto;padding:11px;display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:9px;align-content:start;}
.agc{background:var(--bg2);border:1px solid var(--border);padding:13px 15px;display:flex;flex-direction:column;gap:6px;position:relative;overflow:hidden;}
.agc::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--amber-dim)}
.agc.online::before{background:var(--green);box-shadow:var(--gg)}
.agc.offline::before{background:var(--red)}
.agn{font-family:var(--fh);font-size:1.2rem;letter-spacing:.07em;color:var(--amber2);display:flex;align-items:center;gap:8px;}
.sd{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.online .sd{background:var(--green);box-shadow:var(--gg);animation:pd 2s ease-in-out infinite}
.offline .sd{background:var(--red)}
@keyframes pd{0%,100%{opacity:1}50%{opacity:.35}}
.agkv{display:grid;grid-template-columns:84px 1fr;row-gap:3px;font-size:.75rem}
.ak{color:var(--textdim)}.av{color:var(--text);font-family:var(--fc);font-size:.79rem}
.agn2{font-family:var(--fh);font-size:1.8rem;color:var(--amber);text-align:right;position:absolute;bottom:11px;right:13px;line-height:1;}
.agn3{font-family:var(--fc);font-size:.6rem;color:var(--textdim);text-align:right;position:absolute;bottom:10px;right:13px;padding-top:21px;}
.noa{grid-column:1/-1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:11px;color:var(--textfaint);font-family:var(--fc);font-size:1rem;letter-spacing:.11em;padding:55px;text-align:center;}
/* ANALYTICS */
#pan{grid-template-columns:1fr 1fr;grid-template-rows:1fr 1fr;gap:1px;background:var(--border)}
.anc{background:var(--bg1);display:flex;flex-direction:column;overflow:hidden}
.anc .cb{overflow-y:auto}
#dw{display:flex;align-items:center;justify-content:center;gap:24px;flex:1}
#dsvg{flex-shrink:0}.dlg{display:flex;flex-direction:column;gap:7px}
.dli{display:flex;align-items:center;gap:7px;font-family:var(--fc);font-size:.82rem}
.dlsw{width:12px;height:12px;border-radius:2px;flex-shrink:0}.dlv{color:var(--amber);margin-left:auto;min-width:26px;text-align:right}
#st{width:100%;border-collapse:collapse;font-family:var(--fc);font-size:.79rem}
#st th{text-align:left;color:var(--textdim);font-weight:normal;letter-spacing:.09em;padding:4px 8px;border-bottom:1px solid var(--border2)}
#st td{padding:5px 8px;border-bottom:1px solid var(--border);color:var(--text)}
#st td:last-child{color:var(--amber);text-align:right}
#st tr:hover td{background:var(--bg2)}
#rsvg{width:100%;flex:1}
.rl{fill:none;stroke:var(--amber);stroke-width:1.5;stroke-linejoin:round;stroke-linecap:round}
.rf{stroke:none;fill:url(#ag2)}
.rg{stroke:var(--border);stroke-width:1}.rlt{font-family:var(--fc);font-size:9px;fill:var(--textdim)}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border2)}::-webkit-scrollbar-thumb:hover{background:var(--amber-dim)}
#toasts{position:fixed;bottom:13px;right:13px;z-index:9999;display:flex;flex-direction:column;gap:5px;pointer-events:none}
.toast{background:var(--bg2);border:1px solid var(--border2);border-left:4px solid var(--amber);padding:7px 12px;font-family:var(--fc);font-size:.82rem;color:var(--text);max-width:360px;animation:tin .2s ease,tout .3s ease 3.7s forwards;}
.toast.CRITICAL{border-left-color:var(--critical);color:var(--critical)}.toast.HIGH{border-left-color:var(--high);color:var(--high)}
@keyframes tin{from{opacity:0;transform:translateX(14px)}to{opacity:1;transform:none}}
@keyframes tout{to{opacity:0;transform:translateX(14px)}}
.empty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:9px;color:var(--textfaint);font-family:var(--fc);font-size:.93rem;letter-spacing:.1em;text-align:center;padding:38px;}
.ei{font-size:2rem;opacity:.22}
</style>
</head>
<body>
<div id="app">
<header>
  <div class="logo"><span class="logo-hex">⬡</span>NETSENTINEL
    <span style="font-family:var(--fc);font-size:.8rem;letter-spacing:.18em;color:var(--textdim);margin-left:4px">COMMAND CENTER</span>
  </div>
  <div class="hm">
    <span id="cst">● OFFLINE</span>
    <span>AGENTS: <b id="ha" style="color:var(--amber)">0</b></span>
    <span>ALERTS: <b id="ht" style="color:var(--amber)">0</b></span>
    <span id="clock" class="bl">--:--:--</span>
  </div>
</header>
<nav>
  <button class="tab active" data-tab="o">◈ OVERVIEW</button>
  <button class="tab" data-tab="f">◉ LIVE FEED <span class="bdg" id="bdf">0</span></button>
  <button class="tab" data-tab="ag">◎ AGENTS</button>
  <button class="tab" data-tab="an">◆ ANALYTICS</button>
  <div style="flex:1"></div>
  <button class="tab" id="expb" style="color:var(--textdim);font-size:.78rem">⬇ EXPORT</button>
</nav>
<div class="panel active" id="po">
  <div class="card" id="gc">
    <div class="ch">THREAT LEVEL</div>
    <div class="cb">
      <div class="gr">
        <svg width="185" height="185" viewBox="0 0 185 185">
          <circle class="gbg" cx="92" cy="92" r="78"/>
          <circle class="garc" id="garc" cx="92" cy="92" r="78" stroke-dasharray="490" stroke-dashoffset="490" stroke="var(--amber)"/>
        </svg>
        <div class="gl"><div class="glvl" id="glvl" style="color:var(--amber)">—</div><div class="gsub">THREAT STATUS</div></div>
      </div>
      <div class="sr">
        <div class="ms"><div class="msv c" id="sc">0</div><div class="msl">CRIT</div></div>
        <div class="ms"><div class="msv h" id="sh">0</div><div class="msl">HIGH</div></div>
        <div class="ms"><div class="msv m" id="sm">0</div><div class="msl">MED</div></div>
        <div class="ms"><div class="msv l" id="sl">0</div><div class="msl">LOW</div></div>
      </div>
    </div>
  </div>
  <div class="card" id="tlc">
    <div class="ch">ALERT TIMELINE — 60 MIN <span id="rtb" style="font-family:var(--fc);font-size:.76rem;color:var(--textdim)"></span></div>
    <div class="cb" style="padding:6px"><svg id="spark-svg" preserveAspectRatio="none"></svg></div>
  </div>
  <div class="card" id="catc">
    <div class="ch">TOP CATEGORIES</div>
    <div class="cb" style="padding:9px 13px;overflow-y:auto" id="cats">
      <div class="empty"><div class="ei">◈</div><div>No data yet</div></div>
    </div>
  </div>
  <div class="card" id="critc">
    <div class="ch">CRITICAL / HIGH</div>
    <div class="cb" style="padding:6px">
      <div id="clist"><div class="empty"><div class="ei">◈</div><div>No critical alerts</div></div></div>
    </div>
  </div>
</div>
<div class="panel" id="pf">
  <div class="ftb">
    <button class="fc2 active" data-level="ALL">ALL</button>
    <button class="fc2 CRITICAL" data-level="CRITICAL">☠ CRITICAL</button>
    <button class="fc2 HIGH" data-level="HIGH">⚠ HIGH</button>
    <button class="fc2 MEDIUM" data-level="MEDIUM">▲ MEDIUM</button>
    <button class="fc2" data-level="LOW">● LOW</button>
    <button class="fc2" data-level="INFO">ℹ INFO</button>
    <input class="sb" id="sb2" type="text" placeholder="SEARCH..."/>
    <span class="fcnt" id="fcnt">0 events</span>
  </div>
  <div id="fs"></div>
</div>
<div class="panel" id="pag">
  <div class="agh" id="agh2">REGISTERED AGENTS — 0 online / 0 total</div>
  <div id="agrid">
    <div class="noa"><div style="font-size:2rem;opacity:.18">◎</div><div>NO AGENTS REGISTERED</div>
      <div style="font-size:.76rem;color:var(--textfaint)">Run sentinel_agent.py or sentinel_agent_windows.py</div></div>
  </div>
</div>
<div class="panel" id="pan">
  <div class="anc">
    <div class="ch">SEVERITY DISTRIBUTION</div>
    <div class="cb" style="padding:13px">
      <div id="dw">
        <svg id="dsvg" width="148" height="148" viewBox="0 0 148 148">
          <defs><filter id="gf2"><feGaussianBlur stdDeviation="2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
          <g id="dsegs"></g>
          <text x="74" y="68" text-anchor="middle" fill="var(--amber)" font-family="'Bebas Neue'" font-size="24" id="dtot">0</text>
          <text x="74" y="82" text-anchor="middle" fill="var(--textdim)" font-family="'VT323'" font-size="11">TOTAL</text>
        </svg>
        <div class="dlg" id="dlg"></div>
      </div>
    </div>
  </div>
  <div class="anc">
    <div class="ch">TOP THREAT SOURCES</div>
    <div class="cb" style="padding:0">
      <table id="st"><thead><tr><th>#</th><th>SOURCE</th><th>ALERTS</th></tr></thead><tbody id="stb"></tbody></table>
    </div>
  </div>
  <div class="anc">
    <div class="ch">ALERT RATE — 60 MIN</div>
    <div class="cb" style="padding:8px">
      <svg id="rsvg" preserveAspectRatio="none">
        <defs><linearGradient id="ag2" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stop-color="var(--amber)" stop-opacity=".26"/>
          <stop offset="100%" stop-color="var(--amber)" stop-opacity="0"/>
        </linearGradient></defs>
        <g id="rgg"></g><path id="rfp" class="rf"/><path id="rlp" class="rl"/><g id="rlg"></g>
      </svg>
    </div>
  </div>
  <div class="anc">
    <div class="ch">FULL CATEGORY BREAKDOWN</div>
    <div class="cb" style="padding:9px 13px;overflow-y:auto" id="ancats"></div>
  </div>
</div>
</div>
<div id="toasts"></div>
<script>
'use strict';
let allAlerts=[],activeFilter='ALL',searchStr='',unseen=0,activeTab='o';
let tlData=new Array(60).fill(0),stats={total:0,by_level:{},by_category:{},top_sources:{}},agData=[];
/* BUG-01: API key injected by server so browser can authenticate */
const _SK={{ api_key|tojson }};
/* BUG-04: pass API key as auth token on WS connect */
const socket=io({secure:true,rejectUnauthorized:false,auth:{token:_SK}});
socket.on('connect',()=>{const e=id('cst');e.textContent='● ONLINE';e.classList.add('live');fetchState();});
socket.on('disconnect',()=>{const e=id('cst');e.textContent='● OFFLINE';e.classList.remove('live');});
socket.on('alert',a=>{allAlerts.unshift(a);if(allAlerts.length>2000)allAlerts.length=2000;onNew(a);});
socket.on('stats',s=>{stats=s;rStats();});
socket.on('timeline',t=>{tlData=t;rTL();rRate();});
socket.on('agents',ag=>{agData=ag;rAgents();});
async function fetchState(){
  try{const r=await fetch('/api/state',{headers:{'X-API-Key':_SK}});
  if(!r.ok)return;const d=await r.json();
  allAlerts=d.alerts||[];stats=d.stats||stats;agData=d.agents||[];tlData=d.timeline||tlData;rAll();}catch(e){}
}
function rAll(){rStats();rFeed();rTL();rRate();rAgents();rAnalytics();}
document.querySelectorAll('.tab[data-tab]').forEach(b=>{
  b.addEventListener('click',()=>{
    activeTab=b.dataset.tab;
    document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));b.classList.add('active');
    document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
    id('p'+activeTab).classList.add('active');
    if(activeTab==='f'){unseen=0;const bdg=id('bdf');bdg.textContent='0';bdg.classList.remove('on');}
    if(activeTab==='an')rAnalytics();
    if(activeTab==='o'){rTL();rStats();}
  });
});
id('expb').addEventListener('click',async()=>{
  try{
    const r=await fetch('/api/alerts/export',{headers:{'X-API-Key':_SK}});
    if(!r.ok){console.error('Export failed:',r.status);return;}
    const blob=await r.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');a.href=url;a.download='netsentinel-alerts.json';
    document.body.appendChild(a);a.click();document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }catch(e){console.error('Export error:',e);}
});
document.querySelectorAll('.fc2').forEach(b=>{
  b.addEventListener('click',()=>{document.querySelectorAll('.fc2').forEach(x=>x.classList.remove('active'));b.classList.add('active');activeFilter=b.dataset.level;rFeed();});
});
id('sb2').addEventListener('input',e=>{searchStr=e.target.value.toLowerCase();rFeed();});
function onNew(a){
  if(activeTab!=='f'){unseen++;const bdg=id('bdf');bdg.textContent=unseen>99?'99+':unseen;bdg.classList.add('on');}
  rStats();if(activeTab==='f')prepRow(a);
  if(['CRITICAL','HIGH'].includes(a.level)){addCrit(a);toast(a);}
}
function rStats(){
  const lv=stats.by_level||{};
  setText('sc',lv.CRITICAL||0);setText('sh',lv.HIGH||0);setText('sm',lv.MEDIUM||0);setText('sl',lv.LOW||0);
  setText('ht',stats.total||0);setText('ha',agData.filter(a=>a.online).length);
  rGauge(lv);rCats(stats.by_category||{});
}
function rGauge(lv){
  const c=lv.CRITICAL||0,h=lv.HIGH||0,m=lv.MEDIUM||0;
  let lv2,col,pct;
  if(c>0){lv2='CRITICAL';col='var(--critical)';pct=1;}
  else if(h>5){lv2='HIGH';col='var(--high)';pct=.75;}
  else if(h>0){lv2='ELEVATED';col='var(--orange)';pct=.55;}
  else if(m>0){lv2='MODERATE';col='var(--medium)';pct=.4;}
  else{lv2='NORMAL';col='var(--green)';pct=.15;}
  const circ=2*Math.PI*78;const arc=id('garc');const lbl=id('glvl');
  arc.style.strokeDashoffset=circ*(1-pct);arc.style.stroke=col;
  lbl.textContent=lv2;lbl.style.color=col;lbl.style.textShadow=`0 0 10px ${col}`;
}
function rCats(cats){
  const b=id('cats');const e=Object.entries(cats).sort((a,c)=>c[1]-a[1]).slice(0,14);
  if(!e.length)return;const mx=e[0][1]||1;
  b.innerHTML=e.map(([k,v])=>`<div class="br"><span class="bl2">${esc(k)}</span><div class="bt"><div class="bf" style="width:${Math.round(v/mx*100)}%"></div></div><span class="bc">${v}</span></div>`).join('');
}
function rTL(){
  const svg=id('spark-svg');if(!svg)return;
  const W=svg.clientWidth||380,H=svg.clientHeight||84;
  const data=tlData,mx=Math.max(...data,1),bw=W/data.length,p=4;
  svg.innerHTML=data.map((v,i)=>{
    const bh=Math.max(2,((v/mx)*(H-p*2)));const x=i*bw+1,y=H-p-bh;
    const op=(0.28+(v/mx)*0.72).toFixed(2);
    return `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${(bw-2).toFixed(1)}" height="${bh.toFixed(1)}" fill="var(--amber-dim)" opacity="${op}"/>`;
  }).join('');
  id('rtb').textContent=`${data.slice(-5).reduce((a,b)=>a+b,0)}/5min`;
}
function filtered(){return allAlerts.filter(a=>{if(activeFilter!=='ALL'&&a.level!==activeFilter)return false;if(searchStr&&!`${a.category} ${a.message} ${a.src} ${a.hostname}`.toLowerCase().includes(searchStr))return false;return true;});}
function rFeed(){
  const list=id('fs');const fa=filtered().slice(0,500);
  setText('fcnt',`${fa.length} events`);
  if(!fa.length){list.innerHTML='<div class="empty"><div class="ei">◈</div><div>NO ALERTS MATCH FILTER</div></div>';return;}
  list.innerHTML=fa.map(rh).join('');
  list.querySelectorAll('.ar').forEach(r=>r.addEventListener('click',()=>togDet(r)));
}
function prepRow(a){
  if(activeFilter!=='ALL'&&a.level!==activeFilter)return;
  if(searchStr&&!`${a.category} ${a.message} ${a.src} ${a.hostname}`.toLowerCase().includes(searchStr))return;
  const list=id('fs');const emp=list.querySelector('.empty');if(emp)list.innerHTML='';
  const div=document.createElement('div');div.innerHTML=rh(a);
  const row=div.firstElementChild;row.addEventListener('click',()=>togDet(row));list.prepend(row);
  const rows=list.querySelectorAll('.ar');if(rows.length>500)rows[rows.length-1].remove();
  const cnt=parseInt(id('fcnt').textContent)||0;id('fcnt').textContent=`${cnt+1} events`;
}
function rh(a){
  const sf=JSON.stringify({ts:a.ts,src:a.src,agent_id:a.agent_id,hostname:a.hostname,message:a.message}).replace(/'/g,"&#39;");
  return `<div class="ar ${a.level}" data-id="${a.id}" data-f='${sf}'><span class="lb ${a.level}">${a.level}</span><span class="ats">${ft(a.ts)}</span><span class="acat">${esc(a.category)}</span><span class="amsg" title="${esc(a.message)}">${esc(a.message)}</span><span class="ahost">${esc(a.hostname)}</span></div><div class="adet" id="det-${a.id}"></div>`;
}
function togDet(row){
  const det=id('det-'+row.dataset.id);if(!det)return;
  if(det.classList.contains('open')){det.classList.remove('open');return;}
  const d=JSON.parse(row.dataset.f.replace(/&#39;/g,"'"));
  det.innerHTML=`<div class="dkv"><span class="dk">TIMESTAMP</span><span class="dv">${d.ts}</span><span class="dk">SOURCE</span><span class="dv">${esc(d.src||'—')}</span><span class="dk">AGENT ID</span><span class="dv">${esc(d.agent_id)}</span><span class="dk">HOSTNAME</span><span class="dv">${esc(d.hostname)}</span><span class="dk">MESSAGE</span><span class="dv">${esc(d.message)}</span></div>`;
  det.classList.add('open');
}
function addCrit(a){
  const list=id('clist');const emp=list.querySelector('.empty');if(emp)list.innerHTML='';
  const div=document.createElement('div');div.className='ci';
  div.innerHTML=`<div class="cic">${esc(a.level)} · ${esc(a.category)}</div><div class="cim">${esc(a.message)}</div><div class="cix">${ft(a.ts)} · ${esc(a.hostname)}</div>`;
  list.prepend(div);while(list.children.length>50)list.lastElementChild.remove();
}
function rAgents(){
  const grid=id('agrid');const on=agData.filter(a=>a.online).length;
  setText('ha',on);id('agh2').textContent=`REGISTERED AGENTS — ${on} ONLINE / ${agData.length} TOTAL`;
  if(!agData.length){grid.innerHTML=`<div class="noa"><div style="font-size:2rem;opacity:.18">◎</div><div>NO AGENTS REGISTERED</div><div style="font-size:.74rem;color:var(--textfaint)">Run sentinel_agent.py or sentinel_agent_windows.py</div></div>`;return;}
  grid.innerHTML=agData.map(a=>{
    const st=a.online?'online':'offline';const ago=a.last_seen?ts2(a.last_seen):'—';
    const osr=a.os?`<span class="ak">OS</span><span class="av">${esc(a.os)}</span>`:'';
    return `<div class="agc ${st}"><div class="agn"><div class="sd"></div>${esc(a.hostname)}</div><div class="agkv"><span class="ak">STATUS</span><span class="av">${st.toUpperCase()}</span><span class="ak">IP</span><span class="av">${esc(a.ip||'—')}</span><span class="ak">LAST SEEN</span><span class="av">${ago}</span><span class="ak">SINCE</span><span class="av">${fd(a.first_seen)}</span>${osr}</div><div class="agn2">${a.alert_count}</div><div class="agn3">ALERTS</div></div>`;
  }).join('');
}
function rAnalytics(){rDonut();rSrc();rRate();rAnCats();}
const DC={CRITICAL:'#ff0055',HIGH:'#ff4400',MEDIUM:'#ffaa00',LOW:'#88cc00',INFO:'#00aacc'};
const LV=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
function rDonut(){
  const lv=stats.by_level||{};const tot=LV.reduce((s,l)=>s+(lv[l]||0),0);
  const R=52,CX=74,CY=74,circ=2*Math.PI*R;let off=0,segs='',leg='';
  LV.forEach(l=>{const v=lv[l]||0,pct=tot>0?v/tot:0,len=pct*circ;
    if(len>0){segs+=`<circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="${DC[l]}" stroke-width="22" stroke-dasharray="${len.toFixed(2)} ${(circ-len).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90,${CX},${CY})" filter="url(#gf2)"/>`;off+=len;}
    leg+=`<div class="dli"><div class="dlsw" style="background:${DC[l]}"></div><span style="color:var(--textdim)">${l}</span><span class="dlv">${v}</span></div>`;
  });
  id('dsegs').innerHTML=segs;id('dlg').innerHTML=leg;id('dtot').textContent=tot;
}
function rSrc(){
  const src=stats.top_sources||{};const rows=Object.entries(src).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const tb=id('stb');
  if(!rows.length){tb.innerHTML=`<tr><td colspan="3" style="color:var(--textfaint);padding:16px;text-align:center">No data yet</td></tr>`;return;}
  tb.innerHTML=rows.map(([ip,n],i)=>`<tr><td style="color:var(--textdim)">${i+1}</td><td>${esc(ip)}</td><td>${n}</td></tr>`).join('');
}
function rRate(){
  const svg=id('rsvg');if(!svg)return;
  const W=svg.clientWidth||380,H=svg.clientHeight||105;
  const data=tlData,mx=Math.max(...data,1);
  const p={t:9,r:9,b:21,l:24};const iW=W-p.l-p.r,iH=H-p.t-p.b,xS=iW/(data.length-1);
  const grid=[0,.25,.5,.75,1].map(t=>{const y=p.t+iH*(1-t),v=Math.round(mx*t);return `<line class="rg" x1="${p.l}" y1="${y.toFixed(1)}" x2="${W-p.r}" y2="${y.toFixed(1)}"/><text class="rlt" x="${p.l-4}" y="${(y+3).toFixed(1)}" text-anchor="end">${v}</text>`;}).join('');
  const xl=[0,14,29,44,59].map(i=>{const x=p.l+i*xS;return `<text class="rlt" x="${x.toFixed(1)}" y="${H-4}" text-anchor="middle">-${59-i}m</text>`;}).join('');
  const pts=data.map((v,i)=>`${(p.l+i*xS).toFixed(1)},${(p.t+iH*(1-v/mx)).toFixed(1)}`);
  id('rgg').innerHTML=grid;id('rlg').innerHTML=xl;
  id('rlp').setAttribute('d','M'+pts.join(' L'));
  id('rfp').setAttribute('d',`M${p.l},${p.t+iH} L`+pts.join(' L')+` L${W-p.r},${p.t+iH} Z`);
}
function rAnCats(){
  const cats=stats.by_category||{};const e=Object.entries(cats).sort((a,b)=>b[1]-a[1]);
  const mx=e[0]?.[1]||1;
  id('ancats').innerHTML=e.map(([k,v])=>`<div class="br" style="margin-bottom:5px"><span class="bl2">${esc(k)}</span><div class="bt"><div class="bf" style="width:${Math.round(v/mx*100)}%;background:var(--amber)"></div></div><span class="bc">${v}</span></div>`).join('');
}
function toast(a){
  const tc=id('toasts');const d=document.createElement('div');d.className=`toast ${a.level}`;
  d.textContent=`[${a.level}] ${a.category} — ${a.message.slice(0,86)}`;tc.appendChild(d);setTimeout(()=>d.remove(),4200);
}
function tick(){id('clock').textContent=new Date().toTimeString().slice(0,8);}
setInterval(tick,1000);tick();
window.addEventListener('resize',()=>{rTL();rRate();});
function id(x){return document.getElementById(x);}
function setText(i,v){const e=id(i);if(e)e.textContent=v;}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function ft(iso){try{return new Date(iso).toTimeString().slice(0,8);}catch{return iso;}}
function fd(iso){if(!iso)return'—';try{const d=new Date(iso);return d.toLocaleDateString()+' '+d.toTimeString().slice(0,5);}catch{return iso;}}
function ts2(iso){if(!iso)return'—';try{const s=Math.floor((Date.now()-new Date(iso).getTime())/1000);if(s<60)return`${s}s ago`;if(s<3600)return`${Math.floor(s/60)}m ago`;return`${Math.floor(s/3600)}h ago`;}catch{return'—';}}
</script>
</body>
</html>"""

@app.route("/")
def dashboard():
    # BUG-01 fix: inject API key so browser JS can call /api/state and /api/alerts/export
    return render_template_string(DASHBOARD_HTML, api_key=app.config["API_KEY"])

def main():
    parser=argparse.ArgumentParser(description="NetSentinel Server v4")
    parser.add_argument("--config",default="sentinel_config.json")
    args=parser.parse_args()
    cfg=load_config(args.config)
    app.config["API_KEY"]=cfg["api_key"]
    host=cfg.get("server_host","0.0.0.0"); port=cfg.get("server_port",8443)
    ssl_ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(cfg["server_cert"],cfg["server_key"])
    ssl_ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ssl_ctx.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
    # SEC-04: prune stale agents periodically
    threading.Thread(target=_periodic_prune, daemon=True).start()
    print(f"\n  NETSENTINEL SERVER v4.1  |  https://{{host}}:{{port}}/  |  TLS 1.2+ ECDHE/AES-GCM\n")
    try:
        import gevent.pywsgi
        from geventwebsocket.handler import WebSocketHandler
        server=gevent.pywsgi.WSGIServer((host,port),app,handler_class=WebSocketHandler,ssl_context=ssl_ctx)
        print(f"  Listening on {host}:{port}  —  Ctrl-C to stop\n"); server.serve_forever()
    except KeyboardInterrupt: print("\n  [!] Server stopped.")

if __name__=="__main__":
    main()
