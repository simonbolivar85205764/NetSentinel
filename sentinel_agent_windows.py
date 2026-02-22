#!/usr/bin/env python3
"""
sentinel_agent_windows.py - NetSentinel Windows Agent (v4 + VT-Aware Detectors)

Detection engine redesign (v4):
  VirusTotal is no longer a standalone alert category.  Every behavioural
  detector checks the VT reputation of the relevant external endpoint and
  uses that score to lower alert thresholds and escalate severity.

  VT Risk Tiers (applied per source/destination endpoint):
    CRITICAL  9+ engines malicious  → threshold × 0.10, severity → CRITICAL
    HIGH      3–8 engines malicious → threshold × 0.25, severity +1 level
    MEDIUM    1–2 malicious / 5+ suspicious → threshold × 0.50, severity +1
    LOW       community reputation < −10 → threshold × 0.75, unchanged
    CLEAN     no result / no key → standard thresholds and severities

Network monitoring agent for Windows 10/11 with:
  - Packet capture via Scapy + Npcap
  - System tray icon (right-click menu)
  - Windows Service mode (--install/--start/--stop/--remove)
  - Windows Event Log integration
  - VirusTotal IP + domain reputation (background cache, feeds all detectors)
  - All 8 network threat detectors (VT-aware thresholds & severities)
  - TLS-encrypted alert reporting

Install dependencies:
  pip install scapy requests colorama cryptography pystray Pillow
  pip install pywin32       # optional: Windows Service support
  Download Npcap: https://npcap.com

Usage:
  python sentinel_agent_windows.py              # interactive with tray icon
  python sentinel_agent_windows.py --no-tray   # headless
  python sentinel_agent_windows.py --install   # register as Windows service (Admin)
  python sentinel_agent_windows.py --start
  python sentinel_agent_windows.py --stop
  python sentinel_agent_windows.py --remove
"""

# ===========================================================
#  VIRUSTOTAL SETTINGS  - edit here or in sentinel_config.json
# ===========================================================
VIRUSTOTAL_API_KEY      = ""   # paste key or set env VIRUSTOTAL_API_KEY
VT_MALICIOUS_THRESHOLD  = 3
VT_SUSPICIOUS_THRESHOLD = 5
VT_CACHE_TTL_CLEAN      = 3600
VT_CACHE_TTL_MALICIOUS  = 300
VT_REQUESTS_PER_MINUTE  = 4
VT_SKIP_PRIVATE         = True
# ===========================================================

import argparse
import base64
import collections
import ipaddress
import json
import math
import os
import platform
import queue
import socket
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

if platform.system() != "Windows":
    print("[!] Use sentinel_agent.py on Linux/macOS.")
    sys.exit(1)

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR,
        get_if_list, get_if_addr, conf as scapy_conf,
    )
    scapy_conf.verb = 0
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("[!] pip install requests")

try:
    from colorama import Fore, Style, init as ci; ci(autoreset=True)
except ImportError:
    class _F:
        RED = YELLOW = GREEN = CYAN = MAGENTA = WHITE = ""
    class _S:
        RESET_ALL = BRIGHT = ""
    Fore = _F(); Style = _S()

try:
    import win32evtlog, win32evtlogutil, win32con; EVTLOG_OK = True
except ImportError:
    EVTLOG_OK = False

try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_OK = True
except ImportError:
    TRAY_OK = False

try:
    import win32serviceutil, win32service, win32event, servicemanager; SVC_OK = True
except ImportError:
    SVC_OK = False

# --- constants ---

SERVICE_NAME    = "NetSentinelAgent"
SERVICE_DISPLAY = "NetSentinel Network Monitor Agent"
SERVICE_DESC    = "Monitors network traffic and reports threats to NetSentinel server."

DEFAULT_CFG = {
    "server_host": "127.0.0.1", "server_port": 8443,
    "agent_port": 8444,   # Agent API port — agents POST here; 8443 is GUI-only
    "api_key": "", "ca_cert": "certs\\ca.crt",
    "virustotal_api_key": "", "port_scan_window": 10, "port_scan_threshold": 15,
    "syn_flood_window": 5, "syn_flood_threshold": 200, "icmp_flood_window": 5,
    "icmp_flood_threshold": 100, "dns_tunnel_query_len": 50, "exfil_window": 60,
    "exfil_bytes_threshold": 5000000, "bruteforce_window": 30, "bruteforce_threshold": 30,
    "alert_cooldown": 15,
}

SUSPICIOUS_PORTS = {1080, 4444, 5555, 6666, 6667, 6668, 6669, 8080, 8443, 8888, 9001, 9030, 31337, 12345, 54321, 2323, 65535}
PRIVATE_RANGES   = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")]

AGENT_ID = uuid.uuid4().hex[:16]
HOSTNAME  = socket.gethostname()
OS_TAG    = f"Windows {platform.version()}"


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in PRIVATE_RANGES)
    except Exception:
        return False


def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(msg, c=""):
    print(f"{c}[{ts()}]{Style.RESET_ALL}  {msg}")


def write_evtlog(level, cat, msg):
    if not EVTLOG_OK: return
    try:
        et = {"CRITICAL": win32con.EVENTLOG_ERROR_TYPE, "HIGH": win32con.EVENTLOG_ERROR_TYPE,
              "MEDIUM": win32con.EVENTLOG_WARNING_TYPE}.get(level, win32con.EVENTLOG_INFORMATION_TYPE)
        win32evtlogutil.ReportEvent(SERVICE_NAME, 1, eventType=et, strings=[f"[{level}] {cat}: {msg}"])
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# VIRUSTOTAL ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class VTRateLimiter:
    def __init__(self, rpm):
        self._iv = 60.0 / max(rpm, 1)
        self._lk = threading.Lock()
        self._nxt = 0.0

    def acquire(self):
        with self._lk:
            w = self._nxt - time.monotonic()
            if w > 0:
                time.sleep(w)
            self._nxt = time.monotonic() + self._iv


class VTCache:
    def __init__(self):
        self._s = {}
        self._lk = threading.Lock()

    def get(self, k):
        with self._lk:
            e = self._s.get(k)
            if not e: return None
            x, d = e
            if time.time() > x:
                del self._s[k]
                return None
            return d

    def set(self, k, d, ttl):
        with self._lk:
            self._s[k] = (time.time() + ttl, d)

    def size(self):
        with self._lk:
            return len(self._s)


class VirusTotalChecker:
    """
    Background VT lookup engine.  Results are stored in the cache and
    consumed by the VT-aware detector helpers — no independent alerts fired.
    """
    VT_BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key, rpm=VT_REQUESTS_PER_MINUTE):
        self._key   = api_key
        self._rate  = VTRateLimiter(rpm)
        self._cache = VTCache()
        self._q     = queue.Queue(maxsize=5000)
        self._seen  = set()
        self._slk   = threading.Lock()
        self._stats = collections.defaultdict(int)
        self._stats_lock = threading.Lock()
        self._en    = bool(api_key)
        self._sess  = self._mksess()
        if self._en:
            threading.Thread(target=self._worker, daemon=True, name="VTWorker").start()
            log(f"VirusTotal ACTIVE  (key:{api_key[:8]}...  {rpm} req/min)", Fore.CYAN)
        else:
            log("VirusTotal DISABLED - set VIRUSTOTAL_API_KEY to enable", Fore.YELLOW)

    def enqueue_ip(self, ip, ctx=""):
        if not self._en or (VT_SKIP_PRIVATE and is_private(ip)): return
        self._sub(ip, "ip", ctx)

    def enqueue_domain(self, dom, ctx=""):
        if not self._en: return
        dom = dom.lower().rstrip(".")
        if not dom or "." not in dom or dom.endswith((".local", ".arpa", ".internal", ".lan")): return
        self._sub(dom, "domain", ctx)

    @property
    def stats(self):
        with self._stats_lock: return dict(self._stats)

    @property
    def cache_size(self):
        return self._cache.size()

    def _sub(self, ind, kind, ctx):
        k = f"{kind}:{ind}"
        if self._cache.get(k) is not None: return   # already cached
        with self._slk:
            if k in self._seen: return
            self._seen.add(k)
        try:
            self._q.put_nowait((ind, kind, ctx))
        except queue.Full:
            with self._slk: self._seen.discard(k)

    def _worker(self):
        while True:
            try:
                ind, kind, ctx = self._q.get(timeout=2)
            except queue.Empty:
                continue
            k = f"{kind}:{ind}"
            with self._slk: self._seen.discard(k)
            try:
                r = self._lookup(ind, kind)
                if r is not None:
                    self._cache.set(k, r, VT_CACHE_TTL_MALICIOUS if r.get("malicious", 0) >= VT_MALICIOUS_THRESHOLD else VT_CACHE_TTL_CLEAN)
                    mal = r.get("malicious", 0)
                    sus = r.get("suspicious", 0)
                    if mal >= VT_MALICIOUS_THRESHOLD:
                        log(f"VT cache update: {ind}  {mal} malicious / {sus} suspicious  [tier: {vt_get_tier(ind, kind)}]", Fore.RED)
                        with self._stats_lock: self._stats["cached_malicious"] += 1
                    elif sus >= VT_SUSPICIOUS_THRESHOLD:
                        log(f"VT cache update: {ind}  {sus} suspicious", Fore.YELLOW)
                        with self._stats_lock: self._stats["cached_suspicious"] += 1
            except Exception as e:
                log(f"VT error ({ind}): {e}", Fore.YELLOW)
            finally:
                self._q.task_done()

    def _mksess(self):
        s = requests.Session()
        s.headers.update({"x-apikey": self._key, "Accept": "application/json", "User-Agent": "NetSentinel-WinAgent/4.0"})
        s.mount("https://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["GET"])))
        return s

    def _lookup(self, ind, kind):
        self._rate.acquire()
        with self._stats_lock: self._stats["requests"] += 1
        url = f"{self.VT_BASE}/ip_addresses/{ind}" if kind == "ip" else f"{self.VT_BASE}/domains/{ind}"
        try:
            r = self._sess.get(url, timeout=15)
        except requests.exceptions.RequestException:
            with self._stats_lock: self._stats["errors"] += 1
            return None
        if r.status_code == 404:
            with self._stats_lock: self._stats["not_found"] += 1
            return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total": 0}
        if r.status_code == 429:
            log("VT rate limit - sleeping 60s", Fore.YELLOW)
            time.sleep(60)
            with self._stats_lock: self._stats["rate_limited"] += 1
            return None
        if r.status_code == 401:
            log("VT key rejected (401)", Fore.RED)
            self._en = False
            return None
        if not r.ok:
            with self._stats_lock: self._stats["errors"] += 1
            return None
        try:
            d = r.json()
            at = d["data"]["attributes"]
            st = at["last_analysis_stats"]
            res = {
                "malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
                "harmless": st.get("harmless", 0), "undetected": st.get("undetected", 0),
                "total": sum(st.values()), "country": at.get("country", ""),
                "as_owner": at.get("as_owner", at.get("registrar", "")),
                "reputation": at.get("reputation", 0),
                "categories": list(at.get("categories", {}).values())[:3],
            }
            with self._stats_lock: self._stats["hits"] += 1
            return res
        except Exception:
            with self._stats_lock: self._stats["errors"] += 1
            return None


vt = None


# ══════════════════════════════════════════════════════════════════════════════
# VT-AWARE DETECTION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

VT_TIER_CRITICAL = "CRITICAL"
VT_TIER_HIGH     = "HIGH"
VT_TIER_MEDIUM   = "MEDIUM"
VT_TIER_LOW      = "LOW"
VT_TIER_CLEAN    = "CLEAN"

_VT_THRESHOLD_MULT = {
    VT_TIER_CRITICAL: 0.10,
    VT_TIER_HIGH:     0.25,
    VT_TIER_MEDIUM:   0.50,
    VT_TIER_LOW:      0.75,
    VT_TIER_CLEAN:    1.00,
}

_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def vt_get_tier(target, kind="ip"):
    """Return VT risk tier from cache, or CLEAN if not yet resolved."""
    if vt is None:
        return VT_TIER_CLEAN
    cached = vt._cache.get(f"{kind}:{target}")
    if cached is None:
        return VT_TIER_CLEAN
    mal = cached.get("malicious", 0)
    sus = cached.get("suspicious", 0)
    rep = cached.get("reputation", 0)
    if mal >= 9:                               return VT_TIER_CRITICAL
    if mal >= VT_MALICIOUS_THRESHOLD:          return VT_TIER_HIGH
    if mal >= 1 or sus >= VT_SUSPICIOUS_THRESHOLD: return VT_TIER_MEDIUM
    if rep < -10:                              return VT_TIER_LOW
    return VT_TIER_CLEAN


def vt_adjusted_threshold(base, target, kind="ip"):
    """Scale a detector's base threshold down according to VT reputation."""
    tier = vt_get_tier(target, kind)
    return max(1, math.ceil(base * _VT_THRESHOLD_MULT[tier]))


def vt_adjusted_severity(base_severity, target, kind="ip"):
    """Escalate alert severity based on VT tier of the endpoint."""
    tier = vt_get_tier(target, kind)
    if tier == VT_TIER_CRITICAL:
        return "CRITICAL"
    if tier in (VT_TIER_HIGH, VT_TIER_MEDIUM):
        try:
            idx = _SEVERITY_ORDER.index(base_severity.upper())
            return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]
        except ValueError:
            return base_severity
    return base_severity


def vt_context_suffix(target, kind="ip"):
    """Return a VT context string to append to alert messages, or empty string."""
    if vt is None:
        return ""
    cached = vt._cache.get(f"{kind}:{target}")
    if cached is None:
        return ""
    tier = vt_get_tier(target, kind)
    if tier == VT_TIER_CLEAN:
        return ""
    mal = cached.get("malicious", 0)
    sus = cached.get("suspicious", 0)
    rep = cached.get("reputation", 0)
    parts = []
    if mal: parts.append(f"{mal} malicious")
    if sus: parts.append(f"{sus} suspicious")
    detail = ", ".join(parts) if parts else f"rep={rep}"
    return f"  [VT:{tier} — {detail}]"


# ══════════════════════════════════════════════════════════════════════════════
# ALERT QUEUE & SHIPPER
# ══════════════════════════════════════════════════════════════════════════════

alert_queue = queue.Queue(maxsize=10000)
LCOLS = {"INFO": Fore.CYAN, "LOW": Fore.GREEN, "MEDIUM": Fore.YELLOW, "HIGH": Fore.RED, "CRITICAL": Fore.MAGENTA}
pkt_count = 0; pkt_lock = threading.Lock(); sent_count = 0; fail_count = 0


class AlertShipper(threading.Thread):
    def __init__(self, srv, key, ca):
        super().__init__(daemon=True, name="AlertShipper")
        self.srv = srv.rstrip("/"); self.key = key; self.ca = ca
        self.sess = self._mksess()

    def _mksess(self):
        s = requests.Session()
        ca = self.ca.replace("\\", "/")
        s.verify = ca if Path(ca).exists() else False
        if not s.verify:
            import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            log("WARNING: CA cert not found - TLS verification DISABLED.", Fore.RED)
        s.headers.update({"X-API-Key": self.key, "X-Agent-ID": AGENT_ID, "X-Hostname": HOSTNAME,
                           "Content-Type": "application/json", "User-Agent": "NetSentinel-WinAgent/4.0"})
        s.mount("https://", HTTPAdapter(max_retries=Retry(total=5, backoff_factor=1.5,
                status_forcelist=[500, 502, 503, 504], allowed_methods=["POST"])))
        return s

    def _post(self, p):
        global sent_count, fail_count
        try:
            r = self.sess.post(f"{self.srv}/api/alert", json=p, timeout=10)
            if r.status_code == 201:
                sent_count += 1
                return True
        except Exception:
            pass
        fail_count += 1
        return False

    def heartbeat(self):
        try:
            self.sess.post(f"{self.srv}/api/agent/heartbeat",
                           json={"agent_id": AGENT_ID, "hostname": HOSTNAME, "os": OS_TAG}, timeout=8)
        except Exception:
            pass

    def run(self):
        log(f"AlertShipper -> {self.srv}", Fore.CYAN)
        hb = 0.0
        while True:
            if time.time() - hb > 30:
                self.heartbeat(); hb = time.time()
            try:
                p = alert_queue.get(timeout=1)
            except queue.Empty:
                continue
            self._post(p); alert_queue.task_done()


class Alerter:
    def __init__(self, cd):
        self._cd = {}; self._lk = threading.Lock()
        self.cooldown = cd; self.counts = collections.defaultdict(int)

    def fire(self, level, cat, msg, src=""):
        k = f"{cat}:{src}"; now = time.time()
        with self._lk:
            if now - self._cd.get(k, 0) < self.cooldown: return
            self._cd[k] = now; self.counts[cat] += 1
        c = LCOLS.get(level, Fore.WHITE)
        print(f"{c}{Style.BRIGHT}[{level:<8}]{Style.RESET_ALL}  {ts()}  {Fore.CYAN}{cat}{Style.RESET_ALL}  {msg}")
        if level in ("CRITICAL", "HIGH"):
            write_evtlog(level, cat, msg)
        p = {"level": level, "category": cat, "message": msg, "src": src,
             "agent_id": AGENT_ID, "hostname": HOSTNAME, "os": OS_TAG}
        try:
            alert_queue.put_nowait(p)
        except queue.Full:
            log("Alert queue full", Fore.YELLOW)


alerter = None


class SlidingCounter:
    def __init__(self):
        self._d = collections.defaultdict(collections.deque)
        self._lk = threading.Lock()

    def add(self, k, v=1):
        with self._lk: self._d[k].append((time.time(), v))

    def count(self, k, w):
        c = time.time() - w
        with self._lk:
            dq = self._d[k]
            while dq and dq[0][0] < c: dq.popleft()
            return len(dq)

    def sum(self, k, w):
        c = time.time() - w
        with self._lk:
            dq = self._d[k]
            while dq and dq[0][0] < c: dq.popleft()
            return sum(v for _, v in dq)

    def unique(self, k, w):
        c = time.time() - w
        with self._lk:
            dq = self._d[k]
            while dq and dq[0][0] < c: dq.popleft()
            return {v for _, v in dq}

    def prune_empty(self):
        with self._lk:
            empty = [k for k, dq in self._d.items() if not dq]
            for k in empty: del self._d[k]


# ══════════════════════════════════════════════════════════════════════════════
# DETECTORS — VT-AWARE
# ══════════════════════════════════════════════════════════════════════════════

CFG = DEFAULT_CFG.copy()
pt = SlidingCounter(); syt = SlidingCounter(); it = SlidingCounter()
et = SlidingCounter(); bft = SlidingCounter()
arp_table = {}; arp_lock = threading.Lock()


def detect_port_scan(pkt):
    """VT target: source IP (the scanner). Known-malicious IPs alert sooner."""
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)): return
    src = pkt[IP].src
    if vt and not is_private(src): vt.enqueue_ip(src, ctx="port_scan")
    pt.add(src, pkt[TCP].dport)
    up        = pt.unique(src, CFG["port_scan_window"])
    threshold = vt_adjusted_threshold(CFG["port_scan_threshold"], src)
    if len(up) >= threshold:
        severity = vt_adjusted_severity("HIGH", src)
        alerter.fire(severity, "PORT SCAN",
            f"{src} probed {len(up)} ports in {CFG['port_scan_window']}s "
            f"(sample:{sorted(up)[:8]}...){vt_context_suffix(src)}", src=src)


def detect_syn_flood(pkt):
    """VT target: source IP. Malicious flooders trigger at 10–25% of normal volume."""
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)): return
    f = pkt[TCP].flags
    if not (f & 0x02 and not f & 0x10): return
    src = pkt[IP].src
    if vt and not is_private(src): vt.enqueue_ip(src, ctx="syn_flood")
    syt.add(src)
    n         = syt.count(src, CFG["syn_flood_window"])
    threshold = vt_adjusted_threshold(CFG["syn_flood_threshold"], src)
    if n >= threshold:
        severity = vt_adjusted_severity("CRITICAL", src)
        alerter.fire(severity, "SYN FLOOD",
            f"{src} sent {n} SYNs in {CFG['syn_flood_window']}s{vt_context_suffix(src)}", src=src)


def detect_icmp_flood(pkt):
    """VT target: source IP."""
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)): return
    if pkt[ICMP].type != 8: return
    src = pkt[IP].src
    if vt and not is_private(src): vt.enqueue_ip(src, ctx="icmp_flood")
    it.add(src)
    n         = it.count(src, CFG["icmp_flood_window"])
    threshold = vt_adjusted_threshold(CFG["icmp_flood_threshold"], src)
    if n >= threshold:
        severity = vt_adjusted_severity("HIGH", src)
        alerter.fire(severity, "ICMP FLOOD",
            f"{src} sent {n} ICMP in {CFG['icmp_flood_window']}s{vt_context_suffix(src)}", src=src)


def detect_suspicious_port(pkt):
    """VT target: external endpoint (src if external, else dst)."""
    if not (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))): return
    layer = TCP if pkt.haslayer(TCP) else UDP
    src, dst   = pkt[IP].src, pkt[IP].dst
    sp, dp     = pkt[layer].sport, pkt[layer].dport
    vt_target  = dst if is_private(src) else src
    if vt and not is_private(vt_target): vt.enqueue_ip(vt_target, ctx="suspicious_port")
    for p in (sp, dp):
        if p in SUSPICIOUS_PORTS:
            d = "->" if p == dp else "<-"
            severity = vt_adjusted_severity("MEDIUM", vt_target)
            alerter.fire(severity, "SUSPICIOUS PORT",
                f"{src}:{sp} {d} {dst}:{dp}  (port {p}=C2/backdoor)"
                f"{vt_context_suffix(vt_target)}", src=f"{src}:{p}")
            break


def detect_arp_spoof(pkt):
    """No external endpoint — stays CRITICAL unconditionally."""
    if not pkt.haslayer(ARP): return
    a = pkt[ARP]
    if a.op != 2: return
    ip, mac = a.psrc, a.hwsrc.lower()
    with arp_lock:
        kn = arp_table.get(ip)
        if kn is None:
            if len(arp_table) < 10000: arp_table[ip] = mac
        elif kn != mac:
            alerter.fire("CRITICAL", "ARP SPOOFING",
                f"IP {ip} MAC changed: {kn} -> {mac}  (MITM?)", src=ip)
            arp_table[ip] = mac


def detect_dns_tunnel(pkt):
    """VT target: queried domain. Flagged domains alert on shorter query names."""
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)): return
    try:
        qn = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
    except Exception:
        return
    src    = pkt[IP].src if pkt.haslayer(IP) else "?"
    domain = qn.lower()
    if vt: vt.enqueue_domain(domain, ctx=src)
    threshold = vt_adjusted_threshold(CFG["dns_tunnel_query_len"], domain, kind="domain")
    if len(qn) >= threshold:
        severity = vt_adjusted_severity("MEDIUM", domain, kind="domain")
        alerter.fire(severity, "DNS TUNNELLING",
            f"{src} queried {len(qn)}-char name: {qn[:80]}..."
            f"{vt_context_suffix(domain, kind='domain')}", src=src)


def detect_exfil(pkt):
    """VT target: destination IP (recipient of the exfiltrated data)."""
    if not pkt.haslayer(IP): return
    src = pkt[IP].src
    if not is_private(src): return
    dst = pkt[IP].dst
    if vt and not is_private(dst): vt.enqueue_ip(dst, ctx="exfil")
    et.add(src, len(pkt))
    tot       = et.sum(src, CFG["exfil_window"])
    threshold = vt_adjusted_threshold(CFG["exfil_bytes_threshold"], dst)
    if tot >= threshold:
        severity = vt_adjusted_severity("HIGH", dst)
        alerter.fire(severity, "DATA EXFILTRATION",
            f"{src} sent {tot/1e6:.1f} MB in {CFG['exfil_window']}s → {dst}"
            f"{vt_context_suffix(dst)}", src=src)


def detect_bruteforce(pkt):
    """VT target: source IP (the attacker)."""
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)): return
    f = pkt[TCP].flags
    if not (f & 0x02 and not f & 0x10): return
    BP = {21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900}
    dp = pkt[TCP].dport
    if dp not in BP: return
    src = pkt[IP].src
    if vt and not is_private(src): vt.enqueue_ip(src, ctx="brute_force")
    k  = f"{src}:{dp}"; bft.add(k)
    n         = bft.count(k, CFG["bruteforce_window"])
    threshold = vt_adjusted_threshold(CFG["bruteforce_threshold"], src)
    if n >= threshold:
        svc = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 21: "FTP",
               3306: "MySQL", 5432: "PgSQL", 5900: "VNC", 1433: "MSSQL",
               25: "SMTP", 110: "POP3", 143: "IMAP", 389: "LDAP"}.get(dp, str(dp))
        severity = vt_adjusted_severity("HIGH", src)
        alerter.fire(severity, "BRUTE FORCE",
            f"{src} -> {n} attempts on {dp}/{svc} in {CFG['bruteforce_window']}s"
            f"{vt_context_suffix(src)}", src=src)


def detect_vt_ip(pkt):
    """Passive cache warmer — enqueues all external dst IPs. No alert fired."""
    if vt is None or not pkt.haslayer(IP): return
    dst = pkt[IP].dst
    if VT_SKIP_PRIVATE and is_private(dst): return
    vt.enqueue_ip(dst)


def detect_vt_dns(pkt):
    """Passive cache warmer — enqueues all queried domains. No alert fired."""
    if vt is None or not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)): return
    try:
        qn = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
    except Exception:
        return
    vt.enqueue_domain(qn, ctx=pkt[IP].src if pkt.haslayer(IP) else "")


DETECTORS = [
    detect_port_scan, detect_syn_flood, detect_icmp_flood, detect_suspicious_port,
    detect_arp_spoof, detect_dns_tunnel, detect_exfil, detect_bruteforce,
    detect_vt_ip,   # passive cache warmer
    detect_vt_dns,  # passive cache warmer
]


def dispatch(pkt):
    global pkt_count
    with pkt_lock: pkt_count += 1
    for fn in DETECTORS:
        try: fn(pkt)
        except Exception: pass


# ══════════════════════════════════════════════════════════════════════════════
# STOP EVENT / TRAY / SERVICE
# ══════════════════════════════════════════════════════════════════════════════

_stop = threading.Event()


def _tray_img(colour="green"):
    sz = 64; img = Image.new("RGBA", (sz, sz), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    fill = {"green": (57, 200, 40), "red": (220, 30, 30), "amber": (220, 150, 0)}.get(colour, (57, 200, 40))
    cx = sz // 2
    draw.polygon([(cx-20, 8), (cx+20, 8), (cx+20, 28), (cx, 50), (cx-20, 28)], fill=fill, outline=(255, 255, 255, 120))
    if colour in ("red", "amber"):
        draw.rectangle([cx-3, 20, cx+3, 36], fill=(255, 255, 255))
        draw.ellipse([cx-3, 39, cx+3, 45], fill=(255, 255, 255))
    return img


def build_tray(srv_url):
    if not TRAY_OK: return

    def open_dash(icon, item):
        import webbrowser; webbrowser.open(srv_url)

    def show_st(icon, item):
        with pkt_lock: n = pkt_count
        msg = f"Packets:{n:,}  Alerts sent:{sent_count}  Server:{srv_url}"
        try:
            from plyer import notification
            notification.notify(title="NetSentinel Agent", message=msg, app_name="NetSentinel Agent", timeout=6)
        except Exception:
            print(f"\n[Status] {msg}\n")

    def stop_ag(icon, item):
        _stop.set(); icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem("NetSentinel Agent", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open Dashboard", open_dash, default=True),
        pystray.MenuItem("Show Status", show_st),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Stop Agent", stop_ag),
    )
    icon = pystray.Icon(name="NetSentinelAgent", icon=_tray_img("green"), title="NetSentinel Agent", menu=menu)
    icon.run()


if SVC_OK:
    class NetSentinelService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESC

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._ev = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._ev)
            _stop.set()

        def SvcDoRun(self):
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                                  servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
            run_monitor(no_tray=True)
            win32event.WaitForSingleObject(self._ev, win32event.INFINITE)


# ══════════════════════════════════════════════════════════════════════════════
# STATS REPORTER
# ══════════════════════════════════════════════════════════════════════════════

def stats_reporter(interval=30):
    _pc = 0
    while not _stop.is_set():
        time.sleep(interval)
        _pc += 1
        if _pc % 10 == 0:
            for t in (pt, syt, it, et, bft): t.prune_empty()
        if _stop.is_set(): break
        with pkt_lock: n = pkt_count
        vs = vt.stats if vt else {}
        print(f"\n{Fore.CYAN}{'─'*62}")
        print(f"  Agent {AGENT_ID}  |  {ts()}  |  packets:{n:,}")
        print(f"  Shipped:{sent_count}  Failures:{fail_count}  Queue:{alert_queue.qsize()}")
        print(f"  Detections:{dict(alerter.counts)}")
        if vs:
            print(f"  VT: {vs.get('requests', 0)} reqs  {vs.get('hits', 0)} hits  cache:{vt.cache_size}")
            print(f"  VT cache: malicious={vs.get('cached_malicious', 0)}  suspicious={vs.get('cached_suspicious', 0)}")
        print(f"{'─'*62}{Style.RESET_ALL}\n")


# ══════════════════════════════════════════════════════════════════════════════
# CORE MONITOR
# ══════════════════════════════════════════════════════════════════════════════

def resolve_vt_key(cfg):
    if VIRUSTOTAL_API_KEY: return VIRUSTOTAL_API_KEY
    e = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if e: return e
    return cfg.get("virustotal_api_key", "")


def choose_iface():
    if not SCAPY_OK: return ""
    ifaces = get_if_list()
    if not ifaces:
        print("[!] No interfaces found. Is Npcap installed?"); return ""
    if len(ifaces) == 1: return ifaces[0]
    print(f"\n{Fore.WHITE}Available interfaces:{Style.RESET_ALL}")
    for i, iface in enumerate(ifaces):
        try: ip = get_if_addr(iface)
        except Exception: ip = "?"
        print(f"  [{i}] {iface}  ({ip})")
    while True:
        try: return ifaces[int(input("\nSelect interface (default 0): ").strip() or "0")]
        except (ValueError, IndexError): print("Invalid selection.")


def run_monitor(iface="", no_tray=False):
    global alerter, vt
    cfg_p = Path("sentinel_config.json")
    if cfg_p.exists():
        try:
            CFG.update(json.loads(cfg_p.read_text()))
            log(f"Config loaded from {cfg_p}", Fore.GREEN)
        except json.JSONDecodeError as e:
            log(f"Config JSON error: {e}", Fore.RED); sys.exit(1)
    else:
        log("sentinel_config.json not found - using defaults", Fore.YELLOW)

    host = CFG.get("server_host", "127.0.0.1")
    agent_port = CFG.get("agent_port", 8444)
    gui_port   = CFG.get("server_port", 8443)
    if host in ("0.0.0.0", ""): host = "127.0.0.1"
    srv_url = f"https://{host}:{agent_port}"   # agents POST to agent_port
    api_key = CFG.get("api_key", "")
    ca      = CFG.get("ca_cert", "certs\\ca.crt")
    vt_key  = resolve_vt_key(CFG)
    vt      = VirusTotalChecker(vt_key)
    alerter = Alerter(cooldown=CFG["alert_cooldown"])
    vs      = f"ENABLED ({vt_key[:8]}...)" if vt_key else "DISABLED"

    print(f"""
  +--------------------------------------------------------+
  |   NETSENTINEL  WINDOWS  AGENT  v4                      |
  +--------------------------------------------------------+
  Agent ID   : {AGENT_ID}
  Hostname   : {HOSTNAME}
  OS         : {OS_TAG}
  Agent API  : {srv_url}  ← alerts posted here
  GUI Port   : {gui_port}     ← browser dashboard (not used by agent)
  VirusTotal : {vs}
  Tray icon  : {"yes" if TRAY_OK and not no_tray else "no"}
  Win Service: {"available" if SVC_OK else "pip install pywin32"}

  VT-aware detection active — thresholds and severities scale
  live per endpoint VT tier (CRITICAL/HIGH/MEDIUM/LOW/CLEAN).
""")

    AlertShipper(srv_url, api_key, ca).start()
    threading.Thread(target=stats_reporter, args=(30,), daemon=True).start()

    if not iface: iface = choose_iface()
    if not iface:
        log("No interface - exiting", Fore.RED); return

    print(f"\n{Fore.GREEN}[*] Sniffing on {Style.BRIGHT}{iface}{Style.RESET_ALL} - "
          f"{'right-click tray icon' if TRAY_OK and not no_tray else 'Ctrl-C'} to stop\n")

    def sniff_t():
        try:
            sniff(iface=iface, prn=dispatch, store=False, filter="ip or arp",
                  stop_filter=lambda _: _stop.is_set())
        except OSError as e:
            log(f"Sniffer OSError: {e}. Is Npcap installed?", Fore.RED); _stop.set()
        except Exception as e:
            log(f"Sniffer error: {e}", Fore.RED); _stop.set()

    sniff_thread = threading.Thread(target=sniff_t, daemon=True)
    sniff_thread.start()

    if TRAY_OK and not no_tray:
        build_tray(srv_url)
    else:
        try: _stop.wait()
        except KeyboardInterrupt: _stop.set()

    vs2 = vt.stats if vt else {}
    print(f"\n{Fore.YELLOW}[!] Agent stopped.  Shipped:{sent_count}  Failures:{fail_count}")
    if vs2:
        print(f"    VT requests:{vs2.get('requests', 0)}  cached malicious:{vs2.get('cached_malicious', 0)}")
    print(Style.RESET_ALL)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(description="NetSentinel Windows Agent v4")
    p.add_argument("--no-tray", action="store_true")
    p.add_argument("--iface", default="")
    p.add_argument("--install", action="store_true")
    p.add_argument("--start",   action="store_true")
    p.add_argument("--stop",    action="store_true")
    p.add_argument("--remove",  action="store_true")
    args = p.parse_args()

    if any([args.install, args.start, args.stop, args.remove]):
        if not SVC_OK: sys.exit("[!] pip install pywin32")
        if args.install:
            win32serviceutil.InstallService(
                NetSentinelService._svc_name_, NetSentinelService._svc_display_name_,
                exeName=f'"{sys.executable}" "{os.path.abspath(__file__)}"',
                description=SERVICE_DESC, startType=win32service.SERVICE_AUTO_START,
            )
            print(f"[+] Service installed: {SERVICE_DISPLAY}")
        if args.start:  win32serviceutil.StartService(SERVICE_NAME);  print("[+] Service started.")
        if args.stop:   win32serviceutil.StopService(SERVICE_NAME);   print("[+] Service stopped.")
        if args.remove: win32serviceutil.RemoveService(SERVICE_NAME); print("[+] Service removed.")
        return

    if not SCAPY_OK:
        sys.exit("[!] pip install scapy  and install Npcap from https://npcap.com")
    run_monitor(iface=args.iface, no_tray=args.no_tray)


if __name__ == "__main__":
    if SVC_OK and len(sys.argv) > 1 and sys.argv[1] in ("start", "stop", "remove", "restart", "status"):
        win32serviceutil.HandleCommandLine(NetSentinelService)
    else:
        main()
