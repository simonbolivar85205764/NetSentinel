# NetSentinel v2 — Distributed Network Security Monitor

A production-grade distributed IDS: monitoring agents ship encrypted alerts to a
central server with a real-time cyberpunk-themed GUI dashboard.

```
┌─────────────────────────────────────────────────────────────────┐
│                     Architecture                                │
│                                                                 │
│  Host A                    TLS/HTTPS               Server       │
│  sentinel_agent.py  ──────────────────────►  sentinel_server.py │
│                                                      │          │
│  Host B                                              │ WebSocket │
│  sentinel_agent.py  ──────────────────────►          │          │
│                                                      ▼          │
│  Host C                                         Browser GUI     │
│  sentinel_agent.py  ──────────────────────►  (real-time dash)   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Installation

```bash
# Server + cert generation
pip install flask flask-socketio gevent gevent-websocket cryptography requests

# Each agent host also needs:
pip install scapy requests colorama cryptography
```

---

## Quick Start

### Step 1 — Generate TLS certs & API key (run once, on the server)

```bash
python3 gen_certs.py
```

This creates:
- `certs/ca.crt` — CA certificate (distribute to all agents)
- `certs/server.crt` + `certs/server.key` — server identity
- `sentinel_config.json` — shared config (contains API key)

### Step 2 — Start the server

```bash
python3 sentinel_server.py
# Dashboard at: https://localhost:8443/
```

### Step 3 — Deploy agents

Copy `sentinel_config.json` and `certs/ca.crt` to each host, then:

```bash
sudo python3 sentinel_agent.py --config sentinel_config.json
```

Override the server URL if needed:
```bash
sudo python3 sentinel_agent.py --server https://192.168.1.50:8443
```

---

## Security Model

| Layer | Mechanism |
|-------|-----------|
| **Transport** | TLS 1.2+ enforced, ECDHE key exchange, AES-256-GCM cipher |
| **Auth** | Shared API key in `X-API-Key` header (32 random bytes, URL-safe base64) |
| **Certificate** | Self-signed CA → server cert chain; agents verify server with `ca.crt` |
| **Secrets** | Config file is `chmod 600`; CA private key never leaves the server |
| **Alert integrity** | Every alert carries `agent_id` + `hostname` for attribution |

For production, replace self-signed certs with certs from your internal CA or Let's Encrypt.

---

## Detections

| Category | Trigger |
|----------|---------|
| **Port Scan** | 15+ unique ports from one IP in 10 s |
| **SYN Flood** | 200+ SYN-only packets from one IP in 5 s |
| **ICMP Flood** | 100+ echo-requests from one IP in 5 s |
| **Suspicious Port** | Traffic to/from known C2/backdoor ports |
| **ARP Spoofing** | IP→MAC mapping changes unexpectedly |
| **DNS Tunnelling** | DNS query names longer than 50 characters |
| **Data Exfiltration** | 5 MB+ outbound from one internal host in 60 s |
| **Brute Force** | 30+ SYN attempts to SSH/RDP/FTP/etc. in 30 s |

Thresholds are configurable in `sentinel_config.json`.

---

## Files

```
gen_certs.py          # Run once — generates TLS PKI + API key
sentinel_server.py    # Central server + GUI dashboard
sentinel_agent.py     # Network monitor agent (run on each host)
sentinel_config.json  # Generated config (keep secret)
certs/
  ca.crt              # Distribute to all agent hosts
  ca.key              # Keep on server only
  server.crt
  server.key
```
