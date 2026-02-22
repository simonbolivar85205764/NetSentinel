# NetSentinel v4 — Distributed Network Intrusion Detection System

A production-grade distributed IDS: cross-platform monitoring agents capture
packets, run 8 threat detectors with live VirusTotal-aware thresholds and
severity escalation, and ship encrypted alerts to a central server with a
real-time multi-tab command-center dashboard.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Architecture                                   │
│                                                                         │
│  Linux Host                    TLS 1.2+  /  API Key                     │
│  sentinel_agent.py  ──────────────────────────────────►                 │
│                                                         sentinel_server  │
│  Windows Host                   port 8444 (agent API)  .py             │
│  sentinel_agent_windows.py  ──────────────────────────►  │              │
│    └─ system tray icon                                   │ port 8443    │
│    └─ Windows Service                                    │ WebSocket    │
│    └─ Event Log integration                              │              │
│                                                          ▼              │
│         VirusTotal API v3               Browser GUI                     │
│         ┌─────────────┐                 https://server:8443/            │
│         │  IP / Domain│◄── all agents   ┌───────────────┐              │
│         └─────────────┘    check here   │  Overview     │              │
│                                         │  Live Feed    │              │
│  Port 8443  ─── GUI dashboard only      │  Agents       │              │
│  Port 8444  ─── Agent REST API only     │  Analytics    │              │
│                                         └───────────────┘              │
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

The startup banner prints both URLs:
- **GUI Dashboard** → `https://<host>:8443/` (open in your browser)
- **Agent API** → `https://<host>:8444/` (agents connect here automatically)

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
sudo python3 sentinel_agent.py --server https://192.168.1.50:8444
sudo python3 sentinel_agent.py --iface eth1     # specific interface
```

> **Port note:** `--server` should point to the **agent API port** (default 8444), not the GUI port.
> Agents read `agent_port` from `sentinel_config.json` automatically.

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

## VirusTotal Integration (v4 — VT-Aware Detection)

Every agent checks external IPs and DNS-queried domains against the VirusTotal
API in real time using a non-blocking background thread.  In v4, VT results are
no longer standalone alerts.  Instead, **every behavioural detector reads the
VT reputation of its relevant endpoint** and uses that to automatically lower
its alert threshold and escalate its severity.

### VT Risk Tiers

| Tier | Condition | Threshold multiplier | Severity change |
|---|---|---|---|
| **CRITICAL** | 9+ engines flag malicious | × 0.10 (fire at 10% of normal) | Forced to CRITICAL |
| **HIGH** | 3–8 engines flag malicious | × 0.25 | +1 level |
| **MEDIUM** | 1–2 malicious or 5+ suspicious | × 0.50 | +1 level |
| **LOW** | Community reputation < −10 | × 0.75 | Unchanged (VT note added) |
| **CLEAN** | No result / no API key | × 1.00 | Unchanged |

**Example:** A SYN flood from a CRITICAL-tier IP triggers at 20 SYNs (200 × 0.10)
instead of 200 and is forced to CRITICAL regardless of the base severity.

### VT target per detector

| Detector | VT endpoint checked |
|---|---|
| Port Scan | Source IP (the scanner) |
| SYN Flood | Source IP (the flooder) |
| ICMP Flood | Source IP |
| Suspicious Port | External endpoint (src if external, else dst) |
| ARP Spoofing | N/A — always CRITICAL (no external IP) |
| DNS Tunnelling | Queried domain name |
| Data Exfiltration | Destination IP (recipient of the data) |
| Brute Force | Source IP (the attacker) |

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

Without an API key all detectors still function normally using their base
thresholds and severities (CLEAN tier).

---

## Threat Detectors

All 8 detectors run on every agent.  Base thresholds are configurable in
`sentinel_config.json` and are automatically scaled down at runtime by the
VT tier of the relevant endpoint.

| # | Category | Base Trigger | Base Severity | VT endpoint |
|---|---|---|---|---|
| 1 | **Port Scan** | 15+ unique dst ports from one IP in 10 s | HIGH | Source IP |
| 2 | **SYN Flood** | 200+ SYN-only packets from one IP in 5 s | CRITICAL | Source IP |
| 3 | **ICMP Flood** | 100+ echo-requests from one IP in 5 s | HIGH | Source IP |
| 4 | **Suspicious Port** | Traffic to/from known C2/backdoor ports | MEDIUM | External endpoint |
| 5 | **ARP Spoofing** | IP→MAC mapping changes (MITM detection) | CRITICAL | N/A |
| 6 | **DNS Tunnelling** | DNS query name longer than 50 chars | MEDIUM | Queried domain |
| 7 | **Data Exfiltration** | 5 MB+ outbound from one host in 60 s | HIGH | Destination IP |
| 8 | **Brute Force** | 30+ SYN attempts to SSH/RDP/etc. in 30 s | HIGH | Source IP |

Two passive **VT cache-warmer** functions run alongside the detectors to
pre-populate the cache for all observed external IPs and queried domains.
They do not fire alerts independently.

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
  "gui_port":              8443,
  "agent_port":            8444,
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

| Key | Default | Purpose |
|---|---|---|
| `server_port` / `gui_port` | `8443` | Browser dashboard + SocketIO WebSocket |
| `agent_port` | `8444` | Agent REST API (`/api/alert`, `/api/agent/heartbeat`) |
| `server_host` | `0.0.0.0` | Bind address for both servers |

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

**VT reputation available but detector didn't escalate**
→ VT lookups are async. The cache is populated in the background after the first packet from an IP is seen. Subsequent packets will use the cached tier. For long-running connections, the second alert cycle will already be VT-aware.

**Alerts show `[VT:HIGH — 5 malicious]` in the message**
→ This is expected — the VT context suffix is appended to every alert where the relevant endpoint has a non-CLEAN tier.

**Dashboard shows agent as offline even though it's running**
→ An agent is marked offline after 90 seconds without a heartbeat. Check that the agent can reach the server on port 8443 and the firewall allows it.

**Permission denied on Linux/macOS**
→ Packet capture requires root. Run with `sudo python3 sentinel_agent.py`.
