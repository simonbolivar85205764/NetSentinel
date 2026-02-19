# NetSentinel v3 — Distributed Network Intrusion Detection System

A production-grade distributed IDS: cross-platform monitoring agents capture
packets, run 10 threat detectors (including live VirusTotal reputation checks),
and ship encrypted alerts to a central server with a real-time multi-tab
command-center dashboard.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Architecture                                   │
│                                                                         │
│  Linux Host                    TLS 1.2+  /  API Key                    │
│  sentinel_agent.py  ─────────────────────────────────►                 │
│                                                        sentinel_server  │
│  Windows Host                                          .py              │
│  sentinel_agent_windows.py  ────────────────────────►  │               │
│    └─ system tray icon                                  │ WebSocket     │
│    └─ Windows Service                                   │               │
│    └─ Event Log integration                             ▼               │
│                                                    Browser GUI          │
│  macOS Host                                        https://server:8443/ │
│  sentinel_agent.py  ─────────────────────────────►  ┌───────────────┐  │
│                                                     │ ◈ Overview    │  │
│         VirusTotal API v3                           │ ◉ Live Feed   │  │
│         ┌─────────────┐                             │ ◎ Agents      │  │
│         │  IP / Domain│◄── all agents check here   │ ◆ Analytics   │  │
│         └─────────────┘                             └───────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## What's New in v3

| Feature | Detail |
|---|---|
| **VirusTotal integration** | Every external IP and DNS-queried domain is checked against VT's 90+ engine database |
| **Windows agent** | Full Windows 10/11 agent with system tray, Windows Service, and Event Log |
| **Upgraded dashboard** | 4-tab command-center GUI: Overview, Live Feed, Agents, Analytics |
| **OS tagging** | Agent cards in the dashboard show the host OS (Linux / Windows version) |
| **Alert export** | Download all stored alerts as JSON from the dashboard |
| **60-min rate chart** | Analytics tab shows a line chart of alert rate over the last hour |
| **Top sources table** | Analytics tab ranks most-active attacker IPs / indicators |

---

## Files

```
gen_certs.py                  # Run once — generates TLS PKI + API key
sentinel_server.py            # Central server + 4-tab GUI dashboard
sentinel_agent.py             # Linux / macOS monitoring agent
sentinel_agent_windows.py     # Windows 10/11 agent (tray + service)
sentinel_config.json          # Generated config (treat as secret)
certs/
  ca.crt                      # Distribute to all agent hosts
  ca.key                      # Keep on server only — never distribute
  server.crt
  server.key
```

---

## Installation

### Server

```bash
pip install flask flask-socketio gevent gevent-websocket cryptography
```

### Linux / macOS Agent

```bash
pip install scapy requests colorama cryptography
# macOS: brew install libpcap  (if scapy can't find it)
```

### Windows Agent

```bat
pip install scapy requests colorama cryptography pystray Pillow
pip install pywin32       :: optional — required for Windows Service support
```

Download and install **Npcap** (packet capture driver):
👉 https://npcap.com — choose "Install Npcap in WinPcap API-compatible mode"

---

## Quick Start

### Step 1 — Generate TLS certificates and API key (once, on the server)

```bash
python3 gen_certs.py
```

This creates:
- `certs/ca.crt` — CA certificate to distribute to every agent host
- `certs/server.crt` + `certs/server.key` — server TLS identity
- `sentinel_config.json` — shared config file (contains the API key)

### Step 2 — Start the server

```bash
python3 sentinel_server.py
```

Dashboard is served at **https://localhost:8443/** (or your server's IP).

### Step 3 — Deploy agents

Copy `sentinel_config.json` and `certs/ca.crt` to each agent host, then run:

**Linux / macOS:**
```bash
sudo python3 sentinel_agent.py
```

**Windows (interactive with tray icon):**
```bat
python sentinel_agent_windows.py
```

**Windows (headless, no tray):**
```bat
python sentinel_agent_windows.py --no-tray
```

Override the server URL on any agent if needed:
```bash
sudo python3 sentinel_agent.py --server https://192.168.1.50:8443
sudo python3 sentinel_agent.py --iface eth1          # specific interface
```

---

## VirusTotal Integration

Every agent checks external IPs and DNS-queried domains against the
VirusTotal API in real time using a non-blocking background thread.

### Setting your API key

Get a free key at https://www.virustotal.com/gui/join-us (free tier: 4 requests/min).

Set the key using **any one** of these methods (checked in priority order):

**1. Hardcode in the script (easiest for testing):**
```python
# Near the top of sentinel_agent.py or sentinel_agent_windows.py
VIRUSTOTAL_API_KEY = "your_key_here"
```

**2. Environment variable:**
```bash
export VIRUSTOTAL_API_KEY="your_key_here"          # Linux / macOS
set VIRUSTOTAL_API_KEY=your_key_here               # Windows cmd
$env:VIRUSTOTAL_API_KEY = "your_key_here"          # PowerShell
```

**3. Config file (`sentinel_config.json`):**
```json
{
  "virustotal_api_key": "your_key_here"
}
```

### Alert severity

| VT result | Alert level |
|---|---|
| 9+ engines flag as malicious | CRITICAL |
| 3–8 engines flag as malicious | HIGH |
| 5+ engines flag as suspicious | MEDIUM |
| Community reputation < −10 | LOW |

### Smart rate limiting

The VT engine never exceeds your API tier's request rate. Results are cached
(clean IPs for 1 hour, malicious IPs re-checked after 5 minutes). Duplicate
lookups for the same indicator are deduplicated before hitting the queue, so
seeing the same destination IP 10,000 times triggers exactly one API call.

---

## Threat Detectors

All 10 detectors run on every agent (Linux and Windows). Thresholds are
configurable in `sentinel_config.json`.

| # | Category | Trigger | Default Severity |
|---|---|---|---|
| 1 | **Port Scan** | 15+ unique destination ports from one IP in 10 s | HIGH |
| 2 | **SYN Flood** | 200+ SYN-only packets from one IP in 5 s | CRITICAL |
| 3 | **ICMP Flood** | 100+ echo-requests from one IP in 5 s | HIGH |
| 4 | **Suspicious Port** | Traffic to/from known C2/backdoor ports (4444, 31337, etc.) | MEDIUM |
| 5 | **ARP Spoofing** | IP→MAC mapping changes (MITM detection) | CRITICAL |
| 6 | **DNS Tunnelling** | DNS query name longer than 50 characters | MEDIUM |
| 7 | **Data Exfiltration** | 5 MB+ outbound from one internal host in 60 s | HIGH |
| 8 | **Brute Force** | 30+ SYN attempts to SSH/RDP/FTP/SMB/etc. in 30 s | HIGH |
| 9 | **VT Malicious IP** | Destination IP flagged by 3+ VT engines | HIGH / CRITICAL |
| 10 | **VT Malicious Domain** | DNS-queried domain flagged by 3+ VT engines | HIGH / CRITICAL |

**Suspicious ports monitored:** 1080, 4444, 5555, 6666–6669, 8080, 8443, 8888,
9001, 9030, 12345, 31337, 54321, 2323, 65535

**Brute-force services monitored:** SSH (22), Telnet (23), FTP (21), SMTP (25),
POP3 (110), IMAP (143), LDAP (389), SMB (445), MSSQL (1433), MySQL (3306),
RDP (3389), PostgreSQL (5432), VNC (5900)

---

## Dashboard — 4 Tabs

Open a browser at `https://<server-ip>:8443/` (accept the self-signed cert warning).

### ◈ Overview
- Animated threat-level gauge ring (NORMAL → ELEVATED → MODERATE → HIGH → CRITICAL)
- Live counters for each severity level
- 60-minute alert timeline sparkline
- Top detection categories bar chart
- Real-time sidebar of the most recent CRITICAL/HIGH events

### ◉ Live Feed
- All incoming alerts in reverse chronological order
- Filter by severity level (click the chip buttons)
- Full-text search across category, message, source, and hostname
- Click any row to expand full alert detail (timestamp, source IP, agent ID, message)
- Unseen-alert badge on the tab while you're on another tab

### ◎ Agents
- One card per registered agent showing online/offline status, IP address, OS,
  first-seen / last-seen times, and alert count
- Online pulse animation; offline agents turn red
- Agent cards update live as heartbeats arrive (every 30 s)
- An agent is considered offline if no heartbeat is received for 90 seconds

### ◆ Analytics
- Severity donut chart (all-time distribution)
- Top 10 threat sources table (most-active attacker IPs / VT-flagged indicators)
- 60-minute alert rate area chart with grid lines and axis labels
- Full category breakdown bar chart

**Export:** Click **⬇ EXPORT JSON** in the top bar to download all stored alerts.

---

## Windows Agent — Additional Features

### System Tray Icon

When running interactively, the agent places a shield icon in the Windows
system tray. Right-click it for:
- **Open Dashboard** — launches the server GUI in your default browser
- **Show Status** — displays a Windows toast notification with packet count,
  alert count, and server URL
- **Stop Agent** — gracefully shuts down the agent

### Windows Service

Run as a background service that starts automatically at boot and survives logoff.
All commands require an **Administrator** prompt:

```bat
:: Install (register with Windows SCM)
python sentinel_agent_windows.py --install

:: Start the service
python sentinel_agent_windows.py --start

:: Check status in Services (services.msc) or:
sc query NetSentinelAgent

:: Stop the service
python sentinel_agent_windows.py --stop

:: Uninstall
python sentinel_agent_windows.py --remove
```

The service runs headless (no tray icon). It picks up `sentinel_config.json`
from the same directory as the script.

### Windows Event Log

CRITICAL and HIGH alerts are written to the Windows **Application** Event Log
under the source name `NetSentinelAgent`. You can view them in Event Viewer or
wire them into Windows alerting / SIEM rules.

---

## Security Model

| Layer | Mechanism |
|---|---|
| **Transport** | TLS 1.2+ enforced, ECDHE key exchange, AES-256-GCM cipher suite |
| **Authentication** | Shared 32-byte random API key in `X-API-Key` header |
| **Certificate trust** | Self-signed CA → server cert chain; agents verify server identity with `ca.crt` |
| **Secrets** | `sentinel_config.json` should be `chmod 600`; CA private key never leaves the server |
| **Alert attribution** | Every alert carries `agent_id`, `hostname`, and `os` fields |

For production deployments, replace the self-signed certs with certificates from
your internal CA or Let's Encrypt and rotate the API key periodically by
re-running `gen_certs.py` and redistributing `sentinel_config.json`.

---

## Configuration Reference

`sentinel_config.json` supports these keys. Missing keys fall back to defaults.

```json
{
  "server_host":           "0.0.0.0",
  "server_port":           8443,
  "api_key":               "<generated>",
  "ca_cert":               "certs/ca.crt",
  "server_cert":           "certs/server.crt",
  "server_key":            "certs/server.key",
  "virustotal_api_key":    "",

  "port_scan_window":      10,
  "port_scan_threshold":   15,
  "syn_flood_window":      5,
  "syn_flood_threshold":   200,
  "icmp_flood_window":     5,
  "icmp_flood_threshold":  100,
  "dns_tunnel_query_len":  50,
  "exfil_window":          60,
  "exfil_bytes_threshold": 5000000,
  "bruteforce_window":     30,
  "bruteforce_threshold":  30,
  "alert_cooldown":        15
}
```

`alert_cooldown` (seconds) is the minimum time between repeated alerts for the
same source / category pair — prevents flooding on sustained attacks.

---

## Scaling & Production Notes

- The server holds up to 5,000 alerts in memory. Older alerts roll off automatically.
  Export JSON regularly if you need long-term retention.
- The server handles 100+ agents comfortably on a single process. For larger
  deployments, front it with Redis for shared state.
- The VT free API tier allows 4 requests/minute and 500/day. For busy networks,
  upgrade to a premium tier or reduce `VT_REQUESTS_PER_MINUTE` to stay within limits.
- Open TCP port 8443 on the server firewall for agents and browsers.
- The dashboard's WebSocket connection reconnects automatically on drop.

---

## Troubleshooting

**Agent says "No interfaces found" on Windows**
→ Install Npcap from https://npcap.com and reboot.

**TLS verification disabled (dev mode) warning**
→ The agent can't find `certs/ca.crt`. Make sure you copied both `sentinel_config.json`
  and `certs/ca.crt` to the agent host, and that `ca_cert` in the config points to the
  correct path.

**VirusTotal 401 Unauthorized**
→ Your API key is invalid. Double-check it at https://www.virustotal.com/gui/my-apikey.

**VirusTotal rate limit warnings**
→ You're exceeding your tier's quota. Lower `VT_REQUESTS_PER_MINUTE` in the script,
  or upgrade your VT account.

**Dashboard shows agent as offline even though it's running**
→ An agent is marked offline after 90 seconds without a heartbeat. Check that the
  agent can reach the server on port 8443 and that the firewall allows it.

**Permission denied on Linux/macOS**
→ Packet capture requires root. Run with `sudo python3 sentinel_agent.py`.
