#!/usr/bin/env python3
"""
IoT Security Monitor — Snort-style packet capture, signature matching,
protocol dissection, and anomaly detection for medical/IoT devices.

Usage:
  python sniffer.py                        # sniff live interface
  python sniffer.py --pcap capture.pcap     # offline analysis
  python sniffer.py --rules rules/          # custom rule dir
"""
import os
import re
import sys
import time
import json
import argparse
import ipaddress
import threading
import urllib.request
import urllib.error
from datetime import datetime
from collections import defaultdict
from typing import Optional

from protocols import detect_protocol
from anomaly import AnomalyEngine
from alert import (
    _RedirectHandler,
    configure as configure_alerts,
    configure_auth,
    api_login,
    lookup_device,
    send_detection,
    send_rule_alert,
)

HOME_NET = os.getenv("HOME_NET", "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")
EXTERNAL_NET = os.getenv("EXTERNAL_NET", "!$HOME_NET")
API_BASE = os.getenv("IOT_API_URL", "http://localhost:3000")
AUTH_TOKEN = os.getenv("IOT_AUTH_TOKEN", "")
API_USERNAME = os.getenv("IOT_API_USERNAME", "admin")
API_PASSWORD = os.getenv("IOT_API_PASSWORD", "admin123")

_NO_API = False

configure_alerts(API_BASE, AUTH_TOKEN)
configure_auth(API_USERNAME, API_PASSWORD)

# ── Rule engine ──────────────────────────────────────────────

class Rule:
    def __init__(self, raw: str):
        self.raw = raw
        self.sid = 0
        self.action = "alert"
        self.protocol = "ip"
        self.src_ip = "any"
        self.src_port = "any"
        self.dst_ip = "any"
        self.dst_port = "any"
        self.msg = ""
        self.content = []
        self.fast_pattern = ""
        self.dsize = None
        self.detection_filter = None
        self.parse(raw)

    def parse(self, raw: str):
        m = re.match(
            r'(alert|drop|reject|log)\s+'
            r'(tcp|udp|icmp|ip)\s+'
            r'(\S+)\s+(\S+)\s+->\s+'
            r'(\S+)\s+(\S+)\s*'
            r'\((.*)\)\s*$',
            raw.strip(), re.IGNORECASE
        )
        if not m:
            return
        self.action = m.group(1).lower()
        self.protocol = m.group(2).lower()
        self.src_ip = m.group(3)
        self.src_port = m.group(4)
        self.dst_ip = m.group(5)
        self.dst_port = m.group(6)
        opts = m.group(7)

        # Match quoted values: key:"val"
        for opt in re.finditer(r'(\w+)\s*:\s*"([^"]*)"', opts):
            key, val = opt.group(1).lower(), opt.group(2)
            if key == "msg":
                self.msg = val
            elif key == "content":
                self.content.append(val)
            elif key == "sid":
                self.sid = int(val)

        # Match unquoted values: key:val or key:val;
        for opt in re.finditer(r'(\w+)\s*:\s*(\S+?)(?:;|\s|$)', opts):
            key, val = opt.group(1).lower(), opt.group(2).rstrip(";")
            if key == "sid" and not self.sid:
                self.sid = int(val)
            elif key == "dsize":
                self.dsize = val
            elif key == "detection_filter":
                pass  # handled separately below

        # Match bare flags: fast_pattern, nocase, etc.
        for opt in re.finditer(r'(?<![:\w])\b(fast_pattern|nocase|http_method|http_uri)\b', opts):
            pass

        dsize_m = re.search(r'dsize\s*:\s*([<>]?\d+)', opts)
        if dsize_m:
            self.dsize = dsize_m.group(1)

        df_m = re.search(r'detection_filter\s*:\s*track\s+by_(\w+),\s*count\s+(\d+),\s*seconds\s+(\d+)', opts)
        if df_m:
            self.detection_filter = {
                "track": df_m.group(1), "count": int(df_m.group(2)),
                "seconds": int(df_m.group(3)),
            }

    def match(self, proto: str, src: str, sport: str, dst: str, dport: str,
              payload: bytes, payload_text: str) -> bool:
        if self.protocol != "ip" and proto != self.protocol:
            return False
        if self.src_ip != "any" and not self._match_ip(self.src_ip, src):
            return False
        if self.dst_ip != "any" and not self._match_ip(self.dst_ip, dst):
            return False
        if self.src_port != "any" and sport != self.src_port:
            return False
        if self.dst_port != "any" and dport != self.dst_port:
            return False
        if self.dsize:
            if self.dsize.startswith(">"):
                if len(payload) <= int(self.dsize[1:]):
                    return False
            elif self.dsize.startswith("<"):
                if len(payload) >= int(self.dsize[1:]):
                    return False
            else:
                if len(payload) != int(self.dsize):
                    return False
        for c in self.content:
            if c not in payload_text and c.encode() not in payload:
                return False
        return True

    def _match_ip(self, pattern: str, addr: str) -> bool:
        if pattern.startswith("!"):
            return not self._match_ip(pattern[1:], addr)
        if pattern == "$HOME_NET":
            return any(ipaddress.ip_address(addr) in ipaddress.ip_network(n)
                       for n in HOME_NET.split(",") if n.strip())
        if pattern == "!$HOME_NET" or pattern == "$EXTERNAL_NET":
            return not self._match_ip("$HOME_NET", addr)
        try:
            return ipaddress.ip_address(addr) in ipaddress.ip_network(pattern)
        except:
            return addr == pattern

class RuleEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules: list[Rule] = []
        self.load_rules(rules_dir)

    def load_rules(self, rules_dir: str):
        if not os.path.isdir(rules_dir):
            print(f"[rules] Directory not found: {rules_dir}")
            return
        for fname in sorted(os.listdir(rules_dir)):
            if fname.endswith(".rules"):
                fpath = os.path.join(rules_dir, fname)
                with open(fpath) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            rule = Rule(line)
                            if rule.sid:
                                self.rules.append(rule)
        print(f"[rules] Loaded {len(self.rules)} rules")

    def match(self, proto: str, src: str, sport: str, dst: str, dport: str,
              payload: bytes) -> list[Rule]:
        payload_text = payload.decode("utf-8", errors="replace")
        matched = []
        for rule in self.rules:
            if rule.match(proto, src, sport, dst, dport, payload, payload_text):
                matched.append(rule)
        return matched

# ── Packet processing ────────────────────────────────────────

anomaly = AnomalyEngine()
rule_engine = None  # initialized after args parse

def _resolve_rules_dir(given: str) -> str:
    """Resolve rules directory relative to scanner/ if not absolute."""
    if os.path.isdir(given):
        return given
    alt = os.path.join(os.path.dirname(__file__), given)
    if os.path.isdir(alt):
        return alt
    alt2 = os.path.join(os.path.dirname(__file__), "rules")
    if os.path.isdir(alt2):
        return alt2
    return given

def _init_engine(rules_dir: str = "rules"):
    global rule_engine
    rule_engine = RuleEngine(_resolve_rules_dir(rules_dir))

def _init_api():
    if AUTH_TOKEN:
        print(f"[sniffer] Using provided auth token")
    elif API_BASE and API_BASE != "http://localhost:3000":
        print(f"[sniffer] Attempting API login to {API_BASE}...")
        if api_login():
            print(f"[sniffer] API login successful")
        else:
            print(f"[sniffer] API login failed — alerts may not be authenticated")

def _prefetch_devices():
    """Warm the device cache with all known devices."""
    import ipaddress
    try:
        req = urllib.request.Request(f"{API_BASE}/api/devices")
        if AUTH_TOKEN:
            req.add_header("Cookie", f"iotscanner_token={AUTH_TOKEN}")
        opener = urllib.request.build_opener(_RedirectHandler)
        with opener.open(req, timeout=15) as resp:
            devices = json.loads(resp.read().decode())
            if isinstance(devices, list):
                for d in devices:
                    ip = d.get("ipAddress")
                    if ip:
                        from alert import _device_cache, _device_cache_lock
                        with _device_cache_lock:
                            _device_cache[ip] = {
                                "deviceId": d.get("deviceId"),
                                "deviceType": d.get("deviceType", "Unknown"),
                                "hostname": d.get("hostname", ""),
                                "vendor": d.get("vendor", ""),
                            }
                        device_id_map[ip] = d.get("deviceId")
        print(f"[sniffer] Pre-fetched {len(device_id_map)} devices")
    except Exception as e:
        print(f"[sniffer] Device pre-fetch skipped: {e}")

# Threshold tracking for detection_filter
_track_counters = defaultdict(lambda: defaultdict(lambda: {"count": 0, "window_start": 0}))

def _check_threshold(rule: Rule, src: str, dst: str) -> bool:
    if not rule.detection_filter:
        return True
    df = rule.detection_filter
    key = src if df["track"] == "src" else dst
    tracker = _track_counters[rule.sid][key]
    now = time.time()
    if now - tracker["window_start"] > df["seconds"]:
        tracker["count"] = 0
        tracker["window_start"] = now
    tracker["count"] += 1
    return tracker["count"] <= df["count"]

device_id_map = {}  # ip -> device_id (from server)

def process_packet(packet):
    """Main packet handler — signature match + anomaly + protocol dissection."""
    try:
        if packet.haslayer("IP"):
            ip = packet["IP"]
            src_ip = ip.src
            dst_ip = ip.dst
            proto = "tcp" if packet.haslayer("TCP") else "udp" if packet.haslayer("UDP") else "ip"
            sport = str(packet[proto.upper()].sport) if proto != "ip" else "0"
            dport = str(packet[proto.upper()].dport) if proto != "ip" else "0"
            payload = bytes(packet[proto.upper()].payload) if proto != "ip" else b""
            length = len(packet)

            # MAC address (Ethernet layer)
            src_mac = packet.src if hasattr(packet, "src") else src_ip

            # ── 1. Signature matching ──
            matched_rules = rule_engine.match(proto, src_ip, sport, dst_ip, dport, payload)
            for rule in matched_rules:
                if _check_threshold(rule, src_ip, dst_ip):
                    severity = _severity_from_rule(rule)
                    send_rule_alert(rule.msg, severity, src_ip, dst_ip, int(dport),
                                    device_id_map.get(src_ip))

            # ── 2. Protocol dissection ──
            proto_info = detect_protocol(payload, int(sport), int(dport))

            # ── 3. Anomaly detection ──
            device_type = _lookup_device_type(src_ip)
            anomalies = anomaly.analyze_packet(src_mac, src_ip, dst_ip, int(dport),
                                                length, device_type)
            if anomalies:
                send_detection(anomalies, device_id_map.get(src_ip), src_ip, dst_ip)

    except Exception as e:
        print(f"[sniffer] Error processing packet: {e}")

def _severity_from_rule(rule: Rule) -> str:
    msg_lower = rule.msg.lower()
    if any(w in msg_lower for w in ["critical", "malware", "c2", "exfil"]):
        return "Critical"
    if any(w in msg_lower for w in ["high", "attack", "brute", "rce"]):
        return "High"
    if any(w in msg_lower for w in ["medium", "scan", "info"]):
        return "Medium"
    return "Low"

def _lookup_device_type(ip: str) -> str:
    if ip in device_id_map:
        # Already resolved
        return device_id_map.get(ip + "_type", "Unknown")
    if _NO_API:
        return "Unknown"
    info = lookup_device(ip)
    if info:
        if info.get("deviceId"):
            device_id_map[ip] = info["deviceId"]
            device_id_map[ip + "_type"] = info.get("deviceType", "Unknown")
        return info.get("deviceType", "Unknown")
    return "Unknown"

# ── Live capture ─────────────────────────────────────────────

def live_capture(interface: Optional[str] = None):
    try:
        from scapy.all import sniff
    except ImportError:
        print("[sniffer] scapy not installed. Run: pip install scapy")
        sys.exit(1)

    iface = interface or _detect_interface()
    print(f"[sniffer] Starting live capture on {iface}")
    print(f"[sniffer] Rules loaded: {len(rule_engine.rules)}")
    print(f"[sniffer] Home net: {HOME_NET}")
    print(f"[sniffer] API: {API_BASE}")
    sniff(iface=iface, prn=process_packet, store=False)

def _detect_interface() -> str:
    try:
        from scapy.all import conf
        return conf.iface
    except:
        return "eth0"

# ── PCAP offline analysis ───────────────────────────────────

def pcap_analysis(path: str):
    try:
        from scapy.all import rdpcap
    except ImportError:
        print("[sniffer] scapy not installed")
        sys.exit(1)
    print(f"[sniffer] Analyzing {path}...")
    packets = rdpcap(path)
    total = len(packets)
    print(f"[sniffer] Loaded {total} packets")
    batch_size = max(1, total // 10)
    for idx, pkt in enumerate(packets):
        process_packet(pkt)
        if (idx + 1) % batch_size == 0:
            pct = (idx + 1) / total * 100
            print(f"[sniffer] Progress: {idx+1}/{total} ({pct:.0f}%)")
    print(f"[sniffer] Analysis complete. Flushing alerts...")
    from alert import _flush_batch
    _flush_batch()
    print(f"[sniffer] Done.")

# ── CLI ─────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IoT Security Monitor — Snort-style IDS for medical/IoT devices")
    parser.add_argument("--pcap", help="Analyze a PCAP file instead of live capture")
    parser.add_argument("-i", "--interface", help="Network interface to sniff")
    parser.add_argument("--rules", default="rules", help="Rules directory")
    parser.add_argument("--no-api", action="store_true", help="Skip API calls (offline mode)")
    args = parser.parse_args()

    _NO_API = args.no_api

    _init_engine(args.rules)

    if not args.no_api:
        _init_api()
        _prefetch_devices()
    else:
        print(f"[sniffer] Offline mode — no API calls")

    print(f"[sniffer] Rules loaded: {len(rule_engine.rules)}")
    print(f"[sniffer] API: {API_BASE}")

    if args.pcap:
        pcap_analysis(args.pcap)
    else:
        live_capture(args.interface)
