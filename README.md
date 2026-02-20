# NetSentinel v3 — Distributed Network Intrusion Detection System

A production-grade distributed IDS: cross-platform monitoring agents capture
packets, run 10 threat detectors (including live VirusTotal reputation checks),
and ship encrypted alerts to a central server with a real-time multi-tab
command-center dashboard.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Architecture                                   │
│                                                                         │
│  Linux Host                    TLS 1.2+  /  API Key                     │
│  sentinel_agent.py  ─────────────────────────────────►                  │
│                                                        sentinel_server  │
│  Windows Host                                          .py              │
│  sentinel_agent_windows.py  ────────────────────────►   │               │
│    └─ system tray icon                                  │ WebSocket     │
│    └─ Windows Service                                   │               │
│    └─ Event Log integration                             ▼               │
│                                                    Browser GUI          │
│  macOS Host                                        https://server:8443/ │
│  sentinel_agent.py  ─────────────────────────────►  ┌───────────────┐   │
│                                                     │  Overview     │   │
│         VirusTotal API v3                           │  Live Feed    │   │
│         ┌─────────────┐                             │  Agents       │   │
│         │  IP / Domain│◄── all agents check here    │  Analytics    │   │
│         └─────────────┘                             └───────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

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

The startup banner prints the dashboard URL with the actual host and port.

### Step 3 — Accept the certificate warning in your browser

The server uses a self-signed certificate that browsers don't trust by default.
When you first open the dashboard URL you will see a security warning — this is expected.

**Chrome / Edge:** Click **Advanced** → **Proceed to localhost (unsafe)**

**Firefox:** Click **Advanced** → **Accept the Risk and Continue**

**Safari:** Click **Show Details** → **visit this website**

Once accepted, the browser remembers the exception and the dashboard loads normally on all future visits. The warning does not affect functionality — all traffic is still encrypted with TLS 1.2+.

> **Optional — permanently trust the CA:** Import `certs/ca.crt` into your OS or browser certificate store. On macOS: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt`. On Linux: copy to `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates`.

### Step 4 — Deploy agents

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

Override the server URL if needed:
```bash
sudo python3 sentinel_agent.py --server https://192.168.1.50:8443
sudo python3 sentinel_agent.py --iface eth1     # specific interface
```

---

## Dashboard — 4 Tabs

Open a browser at `https://<server-ip>:8443/` (accept the self-signed cert warning, see Step 3).

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
- Click any row to expand full alert detail
- Unseen-alert badge on the tab while you're on another tab

### ◎ Agents
- One card per registered agent — online/offline status, IP, OS, first/last seen, alert count
- Cards update live via WebSocket (every 30 s heartbeat)
- Agent marked offline after 90 seconds without a heartbeat

### ◆ Analytics
- Severity donut chart (all-time distribution)
- Top 10 threat sources table (most-active attacker IPs)
- 60-minute alert rate area chart
- Full category breakdown bar chart

**Export:** Click **⬇ EXPORT** in the top bar to download all stored alerts as JSON.

---

## VirusTotal Integration

Every agent checks external IPs and DNS-queried domains against the VirusTotal API in real time using a non-blocking background thread.

### Setting your API key

Get a free key at https://www.virustotal.com/gui/join-us (free tier: 4 requests/min).

Set the key using **any one** of these methods (checked in priority order):

**1. Hardcode in the script:**
```python
VIRUSTOTAL_API_KEY = "your_key_here"   # near the top of the agent file
```

**2. Environment variable:**
```bash
export VIRUSTOTAL_API_KEY="your_key_here"          # Linux / macOS
set VIRUSTOTAL_API_KEY=your_key_here               # Windows cmd
$env:VIRUSTOTAL_API_KEY = "your_key_here"          # PowerShell
```

**3. Config file (`sentinel_config.json`):**
```json
{ "virustotal_api_key": "your_key_here" }
```

### Alert severity

| VT result | Alert level |
|---|---|
| 9+ engines flag as malicious | CRITICAL |
| 3–8 engines flag as malicious | HIGH |
| 5+ engines flag as suspicious | MEDIUM |
| Community reputation < −10 | LOW |

---

## Threat Detectors

All 10 detectors run on every agent. Thresholds are configurable in `sentinel_config.json`.

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

---

## Windows Agent — Additional Features

### System Tray Icon

When running interactively, the agent places a shield icon in the Windows system tray. Right-click it for:
- **Open Dashboard** — launches the server GUI in your default browser
- **Show Status** — displays a Windows toast notification with packet count, alert count, and server URL
- **Stop Agent** — gracefully shuts down the agent

### Windows Service

Run as a background service that starts automatically at boot. All commands require an **Administrator** prompt:

```bat
python sentinel_agent_windows.py --install   :: register with Windows SCM
python sentinel_agent_windows.py --start     :: start the service
python sentinel_agent_windows.py --stop      :: stop the service
python sentinel_agent_windows.py --remove    :: uninstall
```

### Windows Event Log

CRITICAL and HIGH alerts are written to the Windows **Application** Event Log under the source name `NetSentinelAgent`, visible in Event Viewer.

---

## Security Model

| Layer | Mechanism |
|---|---|
| **Transport** | TLS 1.2+ enforced, ECDHE key exchange, AES-256-GCM cipher suite |
| **Server auth** | Shared 32-byte random API key in `X-API-Key` header on all REST + WebSocket connections |
| **Certificate trust** | Self-signed CA → server cert chain; agents verify server identity with `ca.crt` |
| **Input validation** | `level` field validated against allowlist; all string fields truncated at server |
| **Rate limiting** | 50 alerts per agent per 5-second window; 500 max registered agents |
| **Secrets** | `sentinel_config.json` should be `chmod 600`; CA private key never leaves the server |
| **Alert attribution** | Every alert carries `agent_id`, `hostname`, and `os` fields |

For production, replace the self-signed certs with certs from your internal CA or Let's Encrypt and rotate the API key periodically by re-running `gen_certs.py`.

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

`alert_cooldown` (seconds) — minimum time between repeated alerts for the same source/category pair.

---

## Troubleshooting

**Browser shows a security certificate warning**
→ This is expected with self-signed certs. Click through the warning (see Step 3 above). The dashboard works normally after accepting. To eliminate the warning permanently, import `certs/ca.crt` into your OS trust store.

**Terminal spammed with SSL traceback errors**
→ Fixed in v4.1. The server now filters expected SSL handshake noise (browser probes, health checks, etc.) from the error log. Only genuine application errors are printed.

**Startup banner shows `{host}:{port}` literally instead of actual values**
→ Fixed in v4.1. Was a Python f-string escaping bug introduced during patching.

**Dashboard tabs load but show no data**
→ Make sure you accepted the browser cert warning first. The dashboard fetches data over HTTPS using the injected API key — if the cert is rejected, all fetches silently fail.

**Agent says "No interfaces found" on Windows**
→ Install Npcap from https://npcap.com and reboot.

**TLS verification disabled warning on agent**
→ The agent can't find `certs/ca.crt`. Make sure you copied both `sentinel_config.json` and `certs/ca.crt` to the agent host and that `ca_cert` in the config points to the correct path.

**VirusTotal 401 Unauthorized**
→ Your API key is invalid. Check it at https://www.virustotal.com/gui/my-apikey.

**VirusTotal rate limit warnings**
→ Exceeding your tier's quota. Lower `VT_REQUESTS_PER_MINUTE` in the agent script, or upgrade your VT account.

**Dashboard shows agent as offline even though it's running**
→ An agent is marked offline after 90 seconds without a heartbeat. Check that the agent can reach the server on port 8443 and the firewall allows it.

**Permission denied on Linux/macOS**
→ Packet capture requires root. Run with `sudo python3 sentinel_agent.py`.
