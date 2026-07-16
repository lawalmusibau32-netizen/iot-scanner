#!/usr/bin/env python3
"""
Scan Agent — polls the API for pending scan jobs and scans registered devices.
Run as a background service:
  python scanner/agent.py
  python scanner/agent.py --interval 30   # check every 30s
  python scanner/agent.py --once          # single run
"""
import os
import sys
import json
import time
import socket
import argparse
import urllib.request
import urllib.error
from datetime import datetime

API_BASE = os.getenv("IOT_API_URL", "https://iot-scanner-one.vercel.app")
AUTH_TOKEN = os.getenv("IOT_AUTH_TOKEN", "")
API_USERNAME = os.getenv("IOT_API_USERNAME", "admin")
API_PASSWORD = os.getenv("IOT_API_PASSWORD", "admin123")

class _RedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return urllib.request.Request(newurl, data=req.data, headers=req.headers, method=req.method)

_OPENER = urllib.request.build_opener(_RedirectHandler)

def log(msg):
    print(f"[agent] {datetime.now().isoformat()} {msg}", flush=True)

def api_login():
    global AUTH_TOKEN
    if AUTH_TOKEN:
        return True
    try:
        payload = json.dumps({"username": API_USERNAME, "password": API_PASSWORD}).encode()
        req = urllib.request.Request(
            f"{API_BASE}/api/auth/login",
            data=payload, headers={"Content-Type": "application/json"}, method="POST",
        )
        with _OPENER.open(req, timeout=15) as resp:
            for cookie in resp.headers.get_all("Set-Cookie") or []:
                if "iotscanner_token" in cookie:
                    start = cookie.find("iotscanner_token=") + len("iotscanner_token=")
                    end = cookie.find(";", start)
                    AUTH_TOKEN = cookie[start:end] if end != -1 else cookie[start:]
                    return True
        return False
    except Exception as e:
        log(f"Login failed: {e}")
        return False

def _headers():
    return {
        "Content-Type": "application/json",
        "Cookie": f"iotscanner_token={AUTH_TOKEN}",
    }

def fetch_pending_scans():
    try:
        req = urllib.request.Request(f"{API_BASE}/api/scans", headers=_headers())
        with _OPENER.open(req, timeout=15) as resp:
            scans = json.loads(resp.read().decode())
            return [s for s in scans if s.get("status") == "pending"]
    except Exception as e:
        log(f"Failed to fetch scans: {e}")
        return []

def fetch_devices():
    try:
        req = urllib.request.Request(f"{API_BASE}/api/devices", headers=_headers())
        with _OPENER.open(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        log(f"Failed to fetch devices: {e}")
        return []

def update_scan(scan_id, status, progress=None, error_log=None, device_count=None):
    data = {"status": status}
    if progress is not None:
        data["progress"] = progress
    if error_log:
        data["errorLog"] = error_log
    if device_count is not None:
        data["deviceCount"] = device_count
    try:
        req = urllib.request.Request(
            f"{API_BASE}/api/scans/{scan_id}",
            data=json.dumps(data).encode(),
            headers=_headers(),
            method="PUT",
        )
        _OPENER.open(req, timeout=10)
    except Exception as e:
        log(f"  Failed to update scan #{scan_id}: {e}")

def send_results(scan_id, scanned_devices):
    results = []
    risks = []
    for dev in scanned_devices:
        device_id = dev.get("deviceId")
        if device_id is None:
            continue
        for port in dev.get("ports", []):
            results.append({
                "deviceId": device_id,
                "port": port["port"],
                "protocol": port.get("protocol", "tcp"),
                "service": port.get("service", "unknown"),
                "banner": port.get("banner", ""),
                "riskLevel": "Medium" if port["port"] in (23, 21) else "Low",
            })
        port_nums = [p["port"] for p in dev.get("ports", [])]
        risk_score = 0
        if 23 in port_nums: risk_score += 4
        if 21 in port_nums: risk_score += 3
        if 22 in port_nums: risk_score += 2
        if 445 in port_nums: risk_score += 3
        if 3389 in port_nums: risk_score += 2
        risk_score += min(len(port_nums) * 0.5, 3)
        risk_score = min(risk_score, 10)
        risks.append({
            "deviceId": device_id,
            "compositeScore": risk_score,
            "cveScore": 0,
            "exposureScore": min(len(port_nums) * 1.5, 10),
            "credentialScore": 5 if any(p in (22, 23) for p in port_nums) else 0,
            "networkScore": 3 if dev.get("deviceType") == "Other" else 1,
        })
    payload = {"results": results, "risks": risks}
    try:
        req = urllib.request.Request(
            f"{API_BASE}/api/scans/{scan_id}/results",
            data=json.dumps(payload).encode(),
            headers=_headers(),
            method="POST",
        )
        with _OPENER.open(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            log(f"  Results posted: {result.get('createdResults', 0)} findings, {result.get('createdRisks', 0)} risk assessments")
    except Exception as e:
        log(f"  Failed to post results: {e}")

def quick_port_scan(ip, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                 1433, 1521, 2049, 3306, 3389, 5432, 6379, 8080, 8443, 9090, 27017]
    results = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) == 0:
                service = socket.getservbyport(port, "tcp") if port < 1024 else _guess_service(port)
                banner = _grab_banner(ip, port)
                results.append({"port": port, "protocol": "tcp", "service": service, "banner": banner})
            s.close()
        except:
            pass
    return results

def _guess_service(port):
    services = {
        1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-proxy",
        8443: "https-alt", 9090: "http-alt", 27017: "mongodb",
    }
    return services.get(port, "unknown")

def _grab_banner(ip, port, timeout=3):
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

def run_scan(scan_job):
    scan_id = scan_job["scanId"]
    scan_type = scan_job.get("scanType", "full")
    target_ip = scan_job.get("targetIp")
    log(f"Processing scan job #{scan_id} ({scan_type})" + (f" targeting {target_ip}" if target_ip else ""))

    update_scan(scan_id, "running", progress=1)

    if target_ip:
        devices = fetch_devices()
        active = [d for d in devices if d.get("isActive") == "Y" and d.get("ipAddress") == target_ip]
        if not active:
            log(f"  No registered device found with IP {target_ip}, scanning anyway")
            active = [{"deviceId": None, "ipAddress": target_ip, "hostname": "", "vendor": "", "deviceType": "Other"}]
        log(f"  Targeting 1 device at {target_ip}")
    else:
        devices = fetch_devices()
        active = [d for d in devices if d.get("isActive") == "Y" and d.get("ipAddress")]
        log(f"Found {len(active)} registered devices to scan")

    if not active:
        update_scan(scan_id, "completed", progress=100, device_count=0)
        send_results(scan_id, [])
        return

    update_scan(scan_id, "running", progress=10, device_count=len(active))

    scanned = []
    for i, device in enumerate(active):
        ip = device["ipAddress"]
        log(f"  [{i+1}/{len(active)}] Scanning {ip} ({device.get('hostname', '') or device.get('deviceType', '?')})")

        update_scan(scan_id, "running", progress=int(10 + (i / len(active)) * 75), device_count=len(active))

        ports = quick_port_scan(ip)

        hostname = device.get("hostname", "")
        if not hostname:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass

        scanned.append({
            "deviceId": device["deviceId"],
            "ipAddress": ip,
            "hostname": hostname,
            "vendor": device.get("vendor", ""),
            "deviceType": device.get("deviceType", "Other"),
            "ports": ports,
            "openPorts": ",".join(str(p["port"]) for p in ports),
            "services": json.dumps({str(p["port"]): p["service"] for p in ports}),
        })

    log(f"  Posting results for {len(scanned)} devices...")
    update_scan(scan_id, "running", progress=90, device_count=len(active))
    send_results(scan_id, scanned)

    update_scan(scan_id, "completed", progress=100, device_count=len(active))
    vuln_count = sum(len(d["ports"]) for d in scanned)
    log(f"Scan #{scan_id} complete — {len(scanned)} devices scanned, {vuln_count} open ports found")

def main():
    parser = argparse.ArgumentParser(description="IoT Scan Agent")
    parser.add_argument("--interval", type=int, default=30, help="Poll interval in seconds")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    args = parser.parse_args()

    log(f"Scan Agent starting (poll every {args.interval}s)")
    if not api_login():
        log("Failed to authenticate — check credentials")
        sys.exit(1)
    log(f"Authenticated, polling {API_BASE}/api/scans")

    while True:
        try:
            pending = fetch_pending_scans()
            for scan in pending:
                run_scan(scan)
            if args.once:
                break
            if not pending:
                time.sleep(args.interval)
        except KeyboardInterrupt:
            log("Shutting down")
            break
        except Exception as e:
            log(f"Error in main loop: {e}")
            time.sleep(args.interval)

if __name__ == "__main__":
    main()
