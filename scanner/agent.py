#!/usr/bin/env python3
"""
Scan Agent — polls the API for pending scan jobs and executes them.
Run as a background service:
  python scanner/agent.py
  python scanner/agent.py --interval 30   # check every 30s
  python scanner/agent.py --once          # single run
"""
import os
import sys
import json
import time
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
    """Get all pending scan jobs from the API."""
    try:
        req = urllib.request.Request(f"{API_BASE}/api/scans", headers=_headers())
        with _OPENER.open(req, timeout=15) as resp:
            scans = json.loads(resp.read().decode())
            pending = [s for s in scans if s.get("status") == "pending"]
            return pending
    except Exception as e:
        log(f"Failed to fetch scans: {e}")
        return []

def run_scan(scan_job):
    """Execute a scan job by shelling out to scanner.py."""
    scan_id = scan_job["scanId"]
    scan_type = scan_job.get("scanType", "full")
    log(f"Processing scan job #{scan_id} ({scan_type})")

    # Mark as running
    _update_scan(scan_id, "running", progress=1)

    # Shell out to scanner.py
    cmd = [
        sys.executable,
        os.path.join(os.path.dirname(__file__), "scanner.py"),
        "--scan-id", str(scan_id),
        "--scan-type", scan_type,
    ]
    log(f"  Running: {' '.join(cmd)}")
    import subprocess
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.stdout:
        for line in result.stdout.strip().split("\n"):
            log(f"  {line}")
    if result.returncode != 0:
        log(f"  Scan #{scan_id} failed (exit {result.returncode})")
        _update_scan(scan_id, "failed", error_log=result.stderr[:500])
    else:
        log(f"  Scan #{scan_id} completed successfully")

def _update_scan(scan_id, status, progress=None, error_log=None):
    data = {"status": status}
    if progress is not None:
        data["progress"] = progress
    if error_log:
        data["errorLog"] = error_log
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
