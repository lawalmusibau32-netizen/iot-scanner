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
from datetime import datetime
from collections import defaultdict
from typing import Optional

from protocols import detect_protocol
from anomaly import AnomalyEngine
from alert import configure as configure_alerts, send_detection, send_rule_alert

HOME_NET = os.getenv("HOME_NET", "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")
EXTERNAL_NET = os.getenv("EXTERNAL_NET", "!$HOME_NET")
API_BASE = os.getenv("IOT_API_URL", "http://localhost:3000")
AUTH_TOKEN = os.getenv("IOT_AUTH_TOKEN", "")

configure_alerts(API_BASE, AUTH_TOKEN)

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

        for opt in re.finditer(r'(\w+)\s*:\s*"([^"]*)"', opts):
            key, val = opt.group(1).lower(), opt.group(2)
            if key == "msg":
                self.msg = val
            elif key == "content":
                self.content.append(val)
            elif key == "fast_pattern":
                self.fast_pattern = val
            elif key == "sid":
                self.sid = int(val)
            elif key == "reference":
                pass
            elif key == "nocase":
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
rule_engine = RuleEngine(os.getenv("RULES_DIR", "rules"))

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
    print(f"[sniffer] Loaded {len(packets)} packets")
    for pkt in packets:
        process_packet(pkt)

# ── CLI ─────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IoT Security Monitor — Snort-style IDS for medical/IoT devices")
    parser.add_argument("--pcap", help="Analyze a PCAP file instead of live capture")
    parser.add_argument("-i", "--interface", help="Network interface to sniff")
    parser.add_argument("--rules", default="rules", help="Rules directory")
    args = parser.parse_args()

    if args.rules:
        rule_engine = RuleEngine(args.rules)

    if args.pcap:
        pcap_analysis(args.pcap)
    else:
        live_capture(args.interface)
