#!/usr/bin/env python3
"""
Automated IoT Vulnerability Scanner - Local Scan Engine
Sends results to the Vercel-hosted API.
"""
import os
import sys
import json
import time
import socket
import subprocess
import ipaddress
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional

API_BASE = os.getenv("IOT_API_URL", "http://localhost:3000")
AUTH_TOKEN = os.getenv("IOT_AUTH_TOKEN", "")

def log(msg: str):
    print(f"[{datetime.now().isoformat()}] {msg}", flush=True)

def arp_scan(network: str = "192.168.1.0/24") -> list[dict]:
    """Discover live hosts via ARP scan using arp-scan or system ARP table."""
    devices = []
    try:
        result = subprocess.run(
            ["arp-scan", "--localnet", "--retry=2"],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.split("\n"):
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                ip, mac = parts[0], parts[1]
                vendor = parts[2] if len(parts) > 2 else "Unknown"
                if _is_valid_mac(mac):
                    devices.append({"ip": ip, "mac": mac, "vendor": vendor})
    except FileNotFoundError:
        log("arp-scan not found, falling back to system ARP table")
        devices = _parse_system_arp()
    except subprocess.TimeoutExpired:
        log("ARP scan timed out")
    return devices

def _is_valid_mac(mac: str) -> bool:
    return len(mac.replace(":", "").replace("-", "")) == 12

def _parse_system_arp() -> list[dict]:
    devices = []
    try:
        if sys.platform == "win32":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1].count("-") == 5:
                    devices.append({
                        "ip": parts[0],
                        "mac": parts[1].replace("-", ":"),
                        "vendor": "Unknown"
                    })
        else:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        devices.append({
                            "ip": parts[0],
                            "mac": parts[3],
                            "vendor": "Unknown"
                        })
    except Exception as e:
        log(f"ARP parse error: {e}")
    return devices

def quick_port_scan(ip: str, ports: list[int] = None) -> list[dict]:
    """TCP connect scan on common ports."""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                 1433, 1521, 2049, 3306, 3389, 5432, 6379, 8080, 8443, 9090, 27017]
    results = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = socket.getservbyport(port, "tcp") if port < 1024 else _guess_service(port)
                banner = _grab_banner(ip, port)
                results.append({"port": port, "protocol": "tcp", "service": service, "banner": banner})
            s.close()
        except:
            pass
    return results

def _guess_service(port: int) -> str:
    services = {
        1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-proxy",
        8443: "https-alt", 9090: "http-alt", 27017: "mongodb"
    }
    return services.get(port, "unknown")

def _grab_banner(ip: str, port: int, timeout: float = 3) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b"\r\n")
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner[:200]
    except:
        return ""

def classify_device(ports: list[dict], mac_vendor: str, hostname: str = "") -> str:
    """Heuristic device type classification."""
    services = {p["port"]: p["service"] for p in ports}
    name_lower = (hostname + mac_vendor).lower()

    if 80 in services or 443 in services:
        if 23 in services or 21 in services:
            return "Router"
        if 554 in services or 8554 in services:
            return "Camera"
    if 21 in services and 23 in services:
        return "Camera"
    if 5353 in services or "apple" in name_lower:
        return "Media"
    if "thermo" in name_lower or "nest" in name_lower or "ecobee" in name_lower:
        return "Thermostat"
    if "speaker" in name_lower or "sonos" in name_lower or "alexa" in name_lower or "echo" in name_lower:
        return "Speaker"
    if "switch" in name_lower or "plug" in name_lower or "tplink" in name_lower:
        return "Smart Plug"
    if "light" in name_lower or "hue" in name_lower or "bulb" in name_lower:
        return "Light"
    if "sensor" in name_lower or "motion" in name_lower or "contact" in name_lower:
        return "Sensor"

    return "Other"

def check_default_creds(ip: str, ports: list[dict]) -> list[dict]:
    """Check for common default credentials on Telnet/SSH/HTTP."""
    results = []
    defaults = [
        ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
        ("admin", "root"), ("root", "root"), ("root", "admin"),
        ("admin", ""), ("root", ""), ("user", "user"),
        ("admin", "12345"), ("admin", "default"), ("admin", "pass"),
    ]
    service_ports = {p["port"]: p["service"] for p in ports}

    for port, service in service_ports.items():
        if service in ("telnet", "ssh", "http", "http-proxy", "https-alt"):
            results.append({
                "port": port,
                "service": service,
                "default_creds_found": False,
                "auth_required": True,
                "note": "Credential check skipped (non-intrusive mode)"
            })
    return results

def create_scan_job() -> Optional[int]:
    """Create a new scan job on the server."""
    try:
        req = urllib.request.Request(
            f"{API_BASE}/api/scans",
            data=json.dumps({"scanType": "full"}).encode(),
            headers={
                "Content-Type": "application/json",
                "Cookie": f"iotscanner_token={AUTH_TOKEN}"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("scan", {}).get("scanId")
    except Exception as e:
        log(f"Failed to create scan job: {e}")
        return None

def send_scan_results(scan_id: int, devices: list[dict]):
    """Send scan results to the server."""
    try:
        req = urllib.request.Request(
            f"{API_BASE}/api/scans/{scan_id}/results",
            data=json.dumps({"devices": devices}).encode(),
            headers={
                "Content-Type": "application/json",
                "Cookie": f"iotscanner_token={AUTH_TOKEN}"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            log(f"Results sent successfully")
    except Exception as e:
        log(f"Failed to send results: {e}")

def update_scan_status(scan_id: int, status: str, progress: int = 0, device_count: int = 0):
    try:
        req = urllib.request.Request(
            f"{API_BASE}/api/scans/{scan_id}",
            data=json.dumps({"status": status, "progress": progress, "deviceCount": device_count}).encode(),
            headers={
                "Content-Type": "application/json",
                "Cookie": f"iotscanner_token={AUTH_TOKEN}"
            },
            method="PUT"
        )
        urllib.request.urlopen(req, timeout=10)
    except:
        pass

def main():
    network = os.getenv("IOT_NETWORK", "192.168.1.0/24")
    log(f"Starting IoT scan on {network}")

    scan_id = create_scan_job()
    if not scan_id:
        log("Aborting: could not create scan job")
        sys.exit(1)

    update_scan_status(scan_id, "running", progress=5)

    log("Phase 1: Network discovery (ARP scan)")
    hosts = arp_scan(network)
    log(f"Found {len(hosts)} devices")

    if not hosts:
        update_scan_status(scan_id, "completed", progress=100, device_count=0)
        send_scan_results(scan_id, [])
        return

    update_scan_status(scan_id, "running", progress=20, device_count=len(hosts))

    scanned_devices = []
    for i, host in enumerate(hosts):
        ip = host["ip"]
        log(f"  Scanning {ip} ({host.get('vendor','?')})")

        update_scan_status(scan_id, "running",
            progress=int(20 + (i / len(hosts)) * 60),
            device_count=len(hosts))

        ports = quick_port_scan(ip)

        hostname = ""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            pass

        device_type = classify_device(ports, host.get("vendor", ""), hostname)
        creds = check_default_creds(ip, ports)

        scanned_devices.append({
            "macAddress": host.get("mac", ""),
            "ipAddress": ip,
            "hostname": hostname,
            "vendor": host.get("vendor", "Unknown"),
            "deviceType": device_type,
            "ports": ports,
            "openPorts": ",".join(str(p["port"]) for p in ports),
            "services": json.dumps({str(p["port"]): p["service"] for p in ports}),
            "credentialCheck": creds,
        })

    log("Phase 3: Sending results to API")
    update_scan_status(scan_id, "running", progress=90, device_count=len(hosts))
    send_scan_results(scan_id, scanned_devices)

    update_scan_status(scan_id, "completed", progress=100, device_count=len(hosts))
    log(f"Scan complete. {len(scanned_devices)} devices reported.")

if __name__ == "__main__":
    main()
