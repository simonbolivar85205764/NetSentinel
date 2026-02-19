#!/usr/bin/env python3
"""
sentinel_agent.py  —  NetSentinel Monitoring Agent  (v3 + VirusTotal)

Captures and analyses network traffic, ships alerts to the central server
over a TLS-authenticated HTTPS connection.  External IPs and DNS-queried
domains are checked against the VirusTotal API for bad reputation.

Dependencies:
    pip install scapy requests colorama cryptography

Run (as root):
    sudo python3 sentinel_agent.py [--config sentinel_config.json] [--server https://host:8443]
"""

# ══════════════════════════════════════════════════════════════════════════════
#  ▶  VIRUSTOTAL SETTINGS  —  edit these before running
# ══════════════════════════════════════════════════════════════════════════════

VIRUSTOTAL_API_KEY = ""          # ← paste your VT API key here
                                 #   or set env-var VIRUSTOTAL_API_KEY
                                 #   or add "virustotal_api_key" to sentinel_config.json

# Thresholds: how many VT engines must flag something before we alert?
VT_MALICIOUS_THRESHOLD  = 3     # engines marking it "malicious"  → HIGH/CRITICAL alert
VT_SUSPICIOUS_THRESHOLD = 5     # engines marking it "suspicious" → MEDIUM alert

# Cache TTL (seconds).  Avoids hammering VT for repeated connections.
VT_CACHE_TTL_CLEAN     = 3600   # 1 h  — remember clean results
VT_CACHE_TTL_MALICIOUS = 300    # 5 min — re-check known-bad items sooner

# VirusTotal free API: 4 requests / minute.  Lower this if you share a key.
VT_REQUESTS_PER_MINUTE = 4

# Only check external (non-RFC-1918) IPs and public domains
VT_SKIP_PRIVATE = True

# ══════════════════════════════════════════════════════════════════════════════

import argparse
import base64
import collections
import ipaddress
import json
import os
import queue
import socket
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

# ── scapy ──────────────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR,
        get_if_list, conf as scapy_conf,
    )
    scapy_conf.verb = 0
except ImportError:
    sys.exit("[!] pip install scapy")

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("[!] pip install requests")

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _F:
        RED = YELLOW = GREEN = CYAN = MAGENTA = WHITE = BLUE = ""
    class _S:
        RESET_ALL = BRIGHT = DIM = ""
    Fore = _F(); Style = _S()

# ══════════════════════════════════════════════════════════════════════════════
# STATIC CONFIG
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_CFG = {
    "server_host":            "127.0.0.1",
    "server_port":            8443,
    "api_key":                "",
    "ca_cert":                "certs/ca.crt",
    "virustotal_api_key":     "",
    # Detection thresholds
    "port_scan_window":       10,
    "port_scan_threshold":    15,
    "syn_flood_window":       5,
    "syn_flood_threshold":    200,
    "icmp_flood_window":      5,
    "icmp_flood_threshold":   100,
    "dns_tunnel_query_len":   50,
    "exfil_window":           60,
    "exfil_bytes_threshold":  5000000,
    "bruteforce_window":      30,
    "bruteforce_threshold":   30,
    "alert_cooldown":         15,
}

SUSPICIOUS_PORTS = {
    1080, 4444, 5555, 6666, 6667, 6668, 6669,
    8080, 8443, 8888, 9001, 9030,
    31337, 12345, 54321, 2323, 65535,
}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]

AGENT_ID = uuid.uuid4().hex[:16]
HOSTNAME  = socket.gethostname()

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def is_private(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(msg, colour=None):
    if colour is None:
        colour = Fore.WHITE
    print(f"{colour}[{ts()}]{Style.RESET_ALL}  {msg}")


# ══════════════════════════════════════════════════════════════════════════════
# VIRUSTOTAL ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class VTRateLimiter:
    """Token-bucket rate limiter — enforces VT free-tier 4 req/min."""
    def __init__(self, rpm):
        self._interval = 60.0 / max(rpm, 1)
        self._lock     = threading.Lock()
        self._next_ok  = 0.0

    def acquire(self):
        with self._lock:
            now  = time.monotonic()
            wait = self._next_ok - now
            if wait > 0:
                time.sleep(wait)
            self._next_ok = time.monotonic() + self._interval


class VTCache:
    """Thread-safe TTL cache for VT results."""

    def __init__(self):
        self._store = {}   # key -> (expiry_time, data_dict)
        self._lock  = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expiry, data = entry
            if time.time() > expiry:
                del self._store[key]
                return None
            return data

    def set(self, key, data, ttl):
        with self._lock:
            self._store[key] = (time.time() + ttl, data)

    def size(self):
        with self._lock:
            return len(self._store)


class VirusTotalChecker:
    """
    Background worker — checks IPs and domains against the VT API v3.

    Items arrive via enqueue_ip() / enqueue_domain() (non-blocking).
    A dedicated daemon thread drains the queue, respects rate limits,
    caches results, and fires alerts through the global alerter.

    Three-level priority for resolving the API key:
        1. VIRUSTOTAL_API_KEY constant in this script
        2. VIRUSTOTAL_API_KEY environment variable
        3. "virustotal_api_key" key in sentinel_config.json
    """

    VT_BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key, rpm=VT_REQUESTS_PER_MINUTE):
        self._api_key  = api_key
        self._rate     = VTRateLimiter(rpm)
        self._cache    = VTCache()
        self._queue    = queue.Queue(maxsize=5000)
        self._seen     = set()
        self._seen_lock = threading.Lock()
        self._stats      = collections.defaultdict(int)
        self._stats_lock = threading.Lock()
        self._enabled    = bool(api_key)
        self._session  = self._make_session()

        if self._enabled:
            t = threading.Thread(target=self._worker, name="VTWorker", daemon=True)
            t.start()
            log(
                f"VirusTotal checker ACTIVE  "
                f"(key: {api_key[:8]}…  "
                f"rate: {rpm} req/min  "
                f"thresholds: malicious>={VT_MALICIOUS_THRESHOLD} / "
                f"suspicious>={VT_SUSPICIOUS_THRESHOLD})",
                Fore.CYAN,
            )
        else:
            log("VirusTotal checker DISABLED — set VIRUSTOTAL_API_KEY to enable", Fore.YELLOW)

    # ── public API ─────────────────────────────────────────────────────────

    def enqueue_ip(self, ip, context=""):
        """Non-blocking: schedule an IP for reputation check."""
        if not self._enabled:
            return
        if VT_SKIP_PRIVATE and is_private(ip):
            return
        self._submit(ip, "ip", context)

    def enqueue_domain(self, domain, context=""):
        """Non-blocking: schedule a domain for reputation check."""
        if not self._enabled:
            return
        domain = domain.lower().rstrip(".")
        if not domain or "." not in domain:
            return
        if domain.endswith((".local", ".arpa", ".internal", ".lan")):
            return
        self._submit(domain, "domain", context)

    @property
    def stats(self):
        with self._stats_lock: return dict(self._stats)

    @property
    def cache_size(self):
        return self._cache.size()

    # ── internals ──────────────────────────────────────────────────────────

    def _submit(self, indicator, kind, context):
        key = f"{kind}:{indicator}"
        # If already cached, evaluate immediately in the calling thread
        cached = self._cache.get(key)
        if cached is not None:
            self._evaluate(indicator, kind, cached, context, from_cache=True)
            return
        # Avoid duplicates in the queue
        with self._seen_lock:
            if key in self._seen:
                return
            self._seen.add(key)
        try:
            self._queue.put_nowait((indicator, kind, context))
        except queue.Full:
            with self._seen_lock:
                self._seen.discard(key)

    def _worker(self):
        while True:
            try:
                indicator, kind, context = self._queue.get(timeout=2)
            except queue.Empty:
                continue

            key = f"{kind}:{indicator}"
            with self._seen_lock:
                self._seen.discard(key)

            try:
                result = self._lookup(indicator, kind)
                if result is not None:
                    is_bad = result.get("malicious", 0) >= VT_MALICIOUS_THRESHOLD
                    self._cache.set(
                        key, result,
                        ttl=VT_CACHE_TTL_MALICIOUS if is_bad else VT_CACHE_TTL_CLEAN,
                    )
                    self._evaluate(indicator, kind, result, context)
            except Exception as exc:
                log(f"VT worker error ({indicator}): {exc}", Fore.YELLOW)
            finally:
                self._queue.task_done()

    def _make_session(self):
        s = requests.Session()
        s.headers.update({
            "x-apikey":   self._api_key,
            "Accept":     "application/json",
            "User-Agent": "NetSentinel-Agent/3.0",
        })
        retry = Retry(
            total=3, backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        s.mount("https://", HTTPAdapter(max_retries=retry))
        return s

    def _lookup(self, indicator, kind):
        """Call VT API v3, return normalised result dict or None on error."""
        self._rate.acquire()
        self._stats["requests"] += 1

        if kind == "ip":
            url = f"{self.VT_BASE}/ip_addresses/{indicator}"
        elif kind == "domain":
            url = f"{self.VT_BASE}/domains/{indicator}"
        else:
            enc = base64.urlsafe_b64encode(indicator.encode()).rstrip(b"=").decode()
            url = f"{self.VT_BASE}/urls/{enc}"

        try:
            r = self._session.get(url, timeout=15)
        except requests.exceptions.RequestException as exc:
            log(f"VT network error ({indicator}): {exc}", Fore.YELLOW)
            with self._stats_lock: self._stats["errors"] += 1
            return None

        if r.status_code == 404:
            with self._stats_lock: self._stats["not_found"] += 1
            return {"malicious": 0, "suspicious": 0, "harmless": 0,
                    "undetected": 0, "total": 0}

        if r.status_code == 429:
            log("VT rate limit hit — sleeping 60 s", Fore.YELLOW)
            time.sleep(60)
            with self._stats_lock: self._stats["rate_limited"] += 1
            return None

        if r.status_code == 401:
            log("VT API key rejected (401 Unauthorized) — disabling checker", Fore.RED)
            self._enabled = False
            return None

        if not r.ok:
            log(f"VT HTTP {r.status_code} for {indicator}", Fore.YELLOW)
            with self._stats_lock: self._stats["errors"] += 1
            return None

        try:
            data  = r.json()
            attrs = data["data"]["attributes"]
            stats = attrs["last_analysis_stats"]

            result = {
                "malicious":  stats.get("malicious",  0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless",   0),
                "undetected": stats.get("undetected", 0),
                "total":      sum(stats.values()),
                # Optional metadata (availability varies by indicator type)
                "country":    attrs.get("country", ""),
                "as_owner":   attrs.get("as_owner", attrs.get("registrar", "")),
                "reputation": attrs.get("reputation", 0),
                "categories": list(attrs.get("categories", {}).values())[:3],
            }
            with self._stats_lock: self._stats["hits"] += 1
            return result

        except (KeyError, ValueError) as exc:
            log(f"VT parse error ({indicator}): {exc}", Fore.YELLOW)
            with self._stats_lock: self._stats["errors"] += 1
            return None

    def _evaluate(self, indicator, kind, result, context, from_cache=False):
        """Translate VT result into an alert when thresholds are breached."""
        mal = result.get("malicious",  0)
        sus = result.get("suspicious", 0)
        tot = result.get("total",      0)
        rep = result.get("reputation", 0)

        cache_tag = " [cached]" if from_cache else ""
        as_owner  = result.get("as_owner", "")
        country   = result.get("country", "")
        cats      = ", ".join(result.get("categories", [])) or None

        meta = f"VT: {mal} malicious / {sus} suspicious / {tot} engines"
        if as_owner:  meta += f"  •  AS: {as_owner}"
        if country:   meta += f"  ({country})"
        if cats:      meta += f"  •  {cats}"
        meta += cache_tag

        label = kind.upper()   # "IP" or "DOMAIN"

        if mal >= VT_MALICIOUS_THRESHOLD:
            # Scale severity: many engines → CRITICAL, few → HIGH
            level = "CRITICAL" if mal >= VT_MALICIOUS_THRESHOLD * 3 else "HIGH"
            alerter.fire(
                level, f"VT MALICIOUS {label}",
                f"{indicator}  —  {meta}",
                src=indicator,
            )
            with self._stats_lock: self._stats["alerted_malicious"] += 1

        elif sus >= VT_SUSPICIOUS_THRESHOLD:
            alerter.fire(
                "MEDIUM", f"VT SUSPICIOUS {label}",
                f"{indicator}  —  {meta}",
                src=indicator,
            )
            with self._stats_lock: self._stats["alerted_suspicious"] += 1

        elif rep < -10:
            # Negative community reputation score (not engine-detected but distrusted)
            alerter.fire(
                "LOW", f"VT LOW REPUTATION {label}",
                f"{indicator}  reputation={rep}  —  {meta}",
                src=indicator,
            )
            with self._stats_lock: self._stats["alerted_reputation"] += 1


# Module-level singleton; instantiated in main() after key is resolved
vt = None


# ══════════════════════════════════════════════════════════════════════════════
# ALERT QUEUE & SHIPPER
# ══════════════════════════════════════════════════════════════════════════════

alert_queue = queue.Queue(maxsize=10000)

LEVEL_COLOURS = {
    "INFO":     Fore.CYAN,
    "LOW":      Fore.GREEN,
    "MEDIUM":   Fore.YELLOW,
    "HIGH":     Fore.RED,
    "CRITICAL": Fore.MAGENTA,
}

pkt_count  = 0
pkt_lock   = threading.Lock()
sent_count = 0
fail_count = 0


class AlertShipper(threading.Thread):
    """Drains alert_queue, POSTs each alert to the central server over TLS."""

    def __init__(self, server_url, api_key, ca_cert):
        super().__init__(daemon=True, name="AlertShipper")
        self.server_url = server_url.rstrip("/")
        self.api_key    = api_key
        self.ca_cert    = ca_cert
        self.session    = self._make_session()

    def _make_session(self):
        s = requests.Session()
        s.verify = self.ca_cert if Path(self.ca_cert).exists() else False
        if not s.verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            log("WARNING: CA cert not found — TLS verification DISABLED. Distribute certs/ca.crt for production.", Fore.RED)
        s.headers.update({
            "X-API-Key":    self.api_key,
            "X-Agent-ID":   AGENT_ID,
            "X-Hostname":   HOSTNAME,
            "Content-Type": "application/json",
            "User-Agent":   "NetSentinel-Agent/3.0",
        })
        retry = Retry(total=5, backoff_factor=1.5,
                      status_forcelist=[500, 502, 503, 504],
                      allowed_methods=["POST"])
        s.mount("https://", HTTPAdapter(max_retries=retry))
        return s

    def _post_alert(self, payload):
        global sent_count, fail_count
        try:
            r = self.session.post(
                f"{self.server_url}/api/alert", json=payload, timeout=10
            )
            if r.status_code == 201:
                sent_count += 1
                return True
            log(f"Server rejected alert: HTTP {r.status_code}", Fore.YELLOW)
        except requests.exceptions.SSLError as exc:
            log(f"TLS error: {exc}", Fore.RED)
        except requests.exceptions.ConnectionError:
            pass
        except Exception as exc:
            log(f"Ship error: {exc}", Fore.RED)
        fail_count += 1
        return False

    def send_heartbeat(self):
        try:
            self.session.post(
                f"{self.server_url}/api/agent/heartbeat",
                json={"agent_id": AGENT_ID, "hostname": HOSTNAME,
                      "os": f"Linux {__import__('platform').release()}"},
                timeout=8,
            )
        except Exception:
            pass

    def run(self):
        log(f"AlertShipper -> {self.server_url}", Fore.CYAN)
        heartbeat_at = 0.0
        while True:
            now = time.time()
            if now - heartbeat_at > 30:
                self.send_heartbeat()
                heartbeat_at = now
            try:
                payload = alert_queue.get(timeout=1)
            except queue.Empty:
                continue
            self._post_alert(payload)
            alert_queue.task_done()


# ══════════════════════════════════════════════════════════════════════════════
# ALERT MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class Alerter:
    def __init__(self, cooldown):
        self._cooldowns = {}
        self._lock      = threading.Lock()
        self.cooldown   = cooldown
        self.counts     = collections.defaultdict(int)

    def fire(self, level, category, message, src=""):
        key = f"{category}:{src}"
        now = time.time()
        with self._lock:
            if now - self._cooldowns.get(key, 0) < self.cooldown:
                return
            self._cooldowns[key] = now
            self.counts[category] += 1

        colour = LEVEL_COLOURS.get(level, Fore.WHITE)
        print(
            f"{colour}{Style.BRIGHT}[{level:<8}]{Style.RESET_ALL}  "
            f"{ts()}  {Fore.CYAN}{category}{Style.RESET_ALL}  {message}"
        )
        try:
            alert_queue.put_nowait({
                "level": level, "category": category,
                "message": message, "src": src,
                "agent_id": AGENT_ID, "hostname": HOSTNAME,
                "os": f"Linux {__import__('platform').release()}",
            })
        except queue.Full:
            log("Alert queue full — dropping alert", Fore.YELLOW)


# ══════════════════════════════════════════════════════════════════════════════
# SLIDING WINDOW COUNTERS
# ══════════════════════════════════════════════════════════════════════════════

class SlidingCounter:
    def __init__(self):
        self._data = collections.defaultdict(collections.deque)
        self._lock = threading.Lock()

    def add(self, key, value=1):
        with self._lock:
            self._data[key].append((time.time(), value))

    def count(self, key, window):
        cutoff = time.time() - window
        with self._lock:
            dq = self._data[key]
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            return len(dq)

    def sum(self, key, window):
        cutoff = time.time() - window
        with self._lock:
            dq = self._data[key]
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            return sum(v for _, v in dq)

    def unique(self, key, window):
        cutoff = time.time() - window
        with self._lock:
            dq = self._data[key]
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            return {v for _, v in dq}

    def prune_empty(self):
        with self._lock:
            empty = [k for k, dq in self._data.items() if not dq]
            for k in empty:
                del self._data[k]


# ══════════════════════════════════════════════════════════════════════════════
# DETECTORS
# ══════════════════════════════════════════════════════════════════════════════

alerter       = None
CFG           = DEFAULT_CFG.copy()
port_tracker  = SlidingCounter()
syn_tracker   = SlidingCounter()
icmp_tracker  = SlidingCounter()
exfil_tracker = SlidingCounter()
bf_tracker    = SlidingCounter()
arp_table     = {}
arp_lock      = threading.Lock()


def detect_port_scan(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)): return
    src = pkt[IP].src
    port_tracker.add(src, pkt[TCP].dport)
    up = port_tracker.unique(src, CFG["port_scan_window"])
    if len(up) >= CFG["port_scan_threshold"]:
        alerter.fire("HIGH", "PORT SCAN",
            f"{src} probed {len(up)} ports in {CFG['port_scan_window']}s "
            f"(sample: {sorted(up)[:8]}...)", src=src)


def detect_syn_flood(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)): return
    flags = pkt[TCP].flags
    if not (flags & 0x02 and not flags & 0x10): return
    src = pkt[IP].src
    syn_tracker.add(src)
    n = syn_tracker.count(src, CFG["syn_flood_window"])
    if n >= CFG["syn_flood_threshold"]:
        alerter.fire("CRITICAL", "SYN FLOOD",
            f"{src} sent {n} SYNs in {CFG['syn_flood_window']}s", src=src)


def detect_icmp_flood(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)): return
    if pkt[ICMP].type != 8: return
    src = pkt[IP].src
    icmp_tracker.add(src)
    n = icmp_tracker.count(src, CFG["icmp_flood_window"])
    if n >= CFG["icmp_flood_threshold"]:
        alerter.fire("HIGH", "ICMP FLOOD",
            f"{src} sent {n} ICMP echo-requests in {CFG['icmp_flood_window']}s", src=src)


def detect_suspicious_port(pkt):
    if not (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))): return
    layer = TCP if pkt.haslayer(TCP) else UDP
    src, dst = pkt[IP].src, pkt[IP].dst
    sport, dport = pkt[layer].sport, pkt[layer].dport
    for port in (sport, dport):
        if port in SUSPICIOUS_PORTS:
            direction = "->" if port == dport else "<-"
            alerter.fire("MEDIUM", "SUSPICIOUS PORT",
                f"{src}:{sport} {direction} {dst}:{dport}  (port {port} = C2/backdoor)",
                src=f"{src}:{port}")
            break


def detect_arp_spoof(pkt):
    if not pkt.haslayer(ARP): return
    arp = pkt[ARP]
    if arp.op != 2: return
    ip, mac = arp.psrc, arp.hwsrc.lower()
    with arp_lock:
        known = arp_table.get(ip)
        if known is None:
            if len(arp_table) < 10000:
                arp_table[ip] = mac
        elif known != mac:
            alerter.fire("CRITICAL", "ARP SPOOFING",
                f"IP {ip} MAC changed: {known} -> {mac}  (MITM?)", src=ip)
            arp_table[ip] = mac


def detect_dns_tunnelling(pkt):
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)): return
    try:
        qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
    except Exception:
        return
    if len(qname) >= CFG["dns_tunnel_query_len"]:
        src = pkt[IP].src if pkt.haslayer(IP) else "?"
        alerter.fire("MEDIUM", "DNS TUNNELLING",
            f"{src} queried {len(qname)}-char name: {qname[:80]}...", src=src)


def detect_exfiltration(pkt):
    if not pkt.haslayer(IP): return
    src = pkt[IP].src
    if not is_private(src): return
    exfil_tracker.add(src, len(pkt))
    total = exfil_tracker.sum(src, CFG["exfil_window"])
    if total >= CFG["exfil_bytes_threshold"]:
        alerter.fire("HIGH", "DATA EXFILTRATION",
            f"{src} sent {total/1000000:.1f} MB in {CFG['exfil_window']}s", src=src)


def detect_brute_force(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)): return
    flags = pkt[TCP].flags
    if not (flags & 0x02 and not flags & 0x10): return
    BRUTE_PORTS = {21,22,23,25,110,143,389,445,1433,3306,3389,5432,5900}
    dport = pkt[TCP].dport
    if dport not in BRUTE_PORTS: return
    src = pkt[IP].src
    key = f"{src}:{dport}"
    bf_tracker.add(key)
    n = bf_tracker.count(key, CFG["bruteforce_window"])
    if n >= CFG["bruteforce_threshold"]:
        svc = {22:"SSH",23:"Telnet",3389:"RDP",445:"SMB",21:"FTP",
               3306:"MySQL",5432:"PgSQL",5900:"VNC",1433:"MSSQL",
               25:"SMTP",110:"POP3",143:"IMAP",389:"LDAP"}.get(dport, str(dport))
        alerter.fire("HIGH", "BRUTE FORCE",
            f"{src} -> {n} attempts on port {dport}/{svc} in {CFG['bruteforce_window']}s",
            src=src)


# ── VirusTotal detectors ───────────────────────────────────────────────────────

def detect_vt_ip_reputation(pkt):
    """Queue every new external destination IP for VT reputation check."""
    if vt is None or not pkt.haslayer(IP): return
    dst = pkt[IP].dst
    if VT_SKIP_PRIVATE and is_private(dst): return
    src = pkt[IP].src
    vt.enqueue_ip(dst, context=src)


def detect_vt_dns_reputation(pkt):
    """Queue every DNS-queried domain name for VT reputation check."""
    if vt is None: return
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)): return
    try:
        qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
    except Exception:
        return
    src = pkt[IP].src if pkt.haslayer(IP) else ""
    vt.enqueue_domain(qname, context=src)


# ══════════════════════════════════════════════════════════════════════════════
# DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════

DETECTORS = [
    detect_port_scan,
    detect_syn_flood,
    detect_icmp_flood,
    detect_suspicious_port,
    detect_arp_spoof,
    detect_dns_tunnelling,
    detect_exfiltration,
    detect_brute_force,
    detect_vt_ip_reputation,    # VirusTotal IP check
    detect_vt_dns_reputation,   # VirusTotal domain check
]


def dispatch(pkt):
    global pkt_count
    with pkt_lock:
        pkt_count += 1
    for fn in DETECTORS:
        try:
            fn(pkt)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# STATS REPORTER
# ══════════════════════════════════════════════════════════════════════════════

def stats_reporter(interval=30):
    _prune_cycle = 0
    while True:
        time.sleep(interval)
        _prune_cycle += 1
        if _prune_cycle % 10 == 0:
            for t in (port_tracker,syn_tracker,icmp_tracker,exfil_tracker,bf_tracker):
                t.prune_empty()
        with pkt_lock:
            n = pkt_count
        vt_stats = vt.stats if vt else {}
        vt_cache = vt.cache_size if vt else 0
        print(f"\n{Fore.CYAN}{'─'*68}")
        print(f"  Agent {AGENT_ID}  |  {ts()}  |  packets: {n:,}")
        print(f"  Alerts shipped: {sent_count}  |  failures: {fail_count}  |  queue: {alert_queue.qsize()}")
        print(f"  Detections: {dict(alerter.counts)}")
        if vt_stats:
            print(
                f"  VT: {vt_stats.get('requests',0)} requests  "
                f"{vt_stats.get('hits',0)} hits  "
                f"{vt_stats.get('errors',0)} errors  "
                f"{vt_cache} cached"
            )
            print(
                f"  VT alerts: malicious={vt_stats.get('alerted_malicious',0)}  "
                f"suspicious={vt_stats.get('alerted_suspicious',0)}  "
                f"low-rep={vt_stats.get('alerted_reputation',0)}"
            )
        print(f"{'─'*68}{Style.RESET_ALL}\n")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def choose_interface():
    ifaces = get_if_list()
    if len(ifaces) == 1:
        return ifaces[0]
    print(f"\n{Fore.WHITE}Available interfaces:{Style.RESET_ALL}")
    for i, iface in enumerate(ifaces):
        print(f"  [{i}] {iface}")
    while True:
        try:
            return ifaces[int(input("\nSelect interface (default 0): ").strip() or "0")]
        except (ValueError, IndexError):
            print("Invalid selection.")


def resolve_vt_key(cfg):
    """
    Resolve the VirusTotal API key with this priority order:
      1. VIRUSTOTAL_API_KEY constant at the top of this script
      2. VIRUSTOTAL_API_KEY environment variable
      3. "virustotal_api_key" field in sentinel_config.json
    """
    if VIRUSTOTAL_API_KEY:
        return VIRUSTOTAL_API_KEY
    env_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if env_key:
        return env_key
    return cfg.get("virustotal_api_key", "")


def main():
    global alerter, CFG, vt

    parser = argparse.ArgumentParser(description="NetSentinel Agent v3")
    parser.add_argument("--config", default="sentinel_config.json")
    parser.add_argument("--server", default="",
                        help="Override server URL, e.g. https://192.168.1.10:8443")
    parser.add_argument("--iface", default="", help="Network interface to sniff")
    args = parser.parse_args()

    # Load config file
    cfg_path = Path(args.config)
    if cfg_path.exists():
        try:
            user_cfg = json.loads(cfg_path.read_text())
            CFG.update(user_cfg)
            print(f"{Fore.GREEN}[v] Config loaded from {cfg_path}{Style.RESET_ALL}")
        except json.JSONDecodeError as e:
            sys.exit(f"[!] Config JSON error: {e}")
    else:
        print(f"{Fore.YELLOW}[!] Config not found — using defaults{Style.RESET_ALL}")

    # Build server URL
    server_url = args.server
    if not server_url:
        host = CFG.get("server_host", "127.0.0.1")
        port = CFG.get("server_port", 8443)
        if host in ("0.0.0.0", ""):
            host = "127.0.0.1"
        server_url = f"https://{host}:{port}"

    api_key = CFG.get("api_key", "")
    ca_cert = CFG.get("ca_cert", "certs/ca.crt")

    # Resolve VirusTotal key and start checker
    vt_key = resolve_vt_key(CFG)
    vt     = VirusTotalChecker(vt_key, rpm=VT_REQUESTS_PER_MINUTE)

    # Alerter
    alerter = Alerter(cooldown=CFG["alert_cooldown"])

    vt_status = (
        f"{Fore.GREEN}ENABLED  (key: {vt_key[:8]}...){Style.RESET_ALL}"
        if vt_key else
        f"{Fore.YELLOW}DISABLED  (set VIRUSTOTAL_API_KEY to enable){Style.RESET_ALL}"
    )

    print(f"""
  +---------------------------------------------------------+
  |   N E T S E N T I N E L   A G E N T   v 3              |
  +---------------------------------------------------------+
  Agent ID   : {AGENT_ID}
  Hostname   : {HOSTNAME}
  Server     : {server_url}
  CA Cert    : {ca_cert}
  VirusTotal : {vt_status}
""")

    # Start background threads
    AlertShipper(server_url, api_key, ca_cert).start()
    threading.Thread(target=stats_reporter, args=(30,), daemon=True).start()

    # Interface selection
    iface = args.iface or choose_interface()
    print(f"\n{Fore.GREEN}[*] Sniffing on {Style.BRIGHT}{iface}{Style.RESET_ALL} — Ctrl-C to stop\n")

    try:
        sniff(iface=iface, prn=dispatch, store=False, filter="ip or arp")
    except PermissionError:
        sys.exit(f"\n{Fore.RED}[!] Run with:  sudo python3 {sys.argv[0]}{Style.RESET_ALL}")
    except KeyboardInterrupt:
        vt_stats = vt.stats if vt else {}
        print(f"\n{Fore.YELLOW}[!] Stopped.")
        print(f"    Alerts shipped : {sent_count}  |  failures: {fail_count}")
        if vt_stats:
            print(
                f"    VT requests    : {vt_stats.get('requests', 0)}  "
                f"| VT alerts fired: "
                f"{vt_stats.get('alerted_malicious', 0) + vt_stats.get('alerted_suspicious', 0)}"
            )
        print(Style.RESET_ALL)


if __name__ == "__main__":
    main()
