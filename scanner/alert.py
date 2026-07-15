"""
Alert pipeline — formats detections and pushes them to the server API.
"""
import json
import time
import urllib.request
import urllib.error
import threading
from collections import deque
from typing import Optional

class _RedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if code in (301, 302, 303, 307, 308):
            new_req = urllib.request.Request(
                newurl,
                data=req.data,
                headers=req.headers,
                method=req.method,
                origin_req_host=req.origin_req_host,
                unverifiable=True,
            )
            return new_req
        return None

API_BASE = None
AUTH_TOKEN = None
API_USERNAME = ""
API_PASSWORD = ""

_batch = deque(maxlen=500)
_batch_lock = threading.Lock()
_flush_timer: Optional[threading.Timer] = None

# Device cache: ip -> {"deviceType": str, "deviceId": int}
_device_cache = {}
_device_cache_lock = threading.Lock()

def configure(api_base: str, auth_token: str):
    global API_BASE, AUTH_TOKEN
    API_BASE = api_base
    AUTH_TOKEN = auth_token

def configure_auth(username: str, password: str):
    global API_USERNAME, API_PASSWORD
    API_USERNAME = username
    API_PASSWORD = password

def api_login() -> bool:
    """Authenticate with the server and store the session token."""
    global AUTH_TOKEN
    if not API_BASE or not API_USERNAME:
        return False
    try:
        payload = json.dumps({"username": API_USERNAME, "password": API_PASSWORD}).encode()
        req = urllib.request.Request(
            f"{API_BASE}/api/auth/login",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        opener = urllib.request.build_opener(_RedirectHandler)
        with opener.open(req, timeout=15) as resp:
            for cookie in resp.headers.get_all("Set-Cookie") or []:
                if "iotscanner_token" in cookie:
                    start = cookie.find("iotscanner_token=") + len("iotscanner_token=")
                    end = cookie.find(";", start)
                    if end == -1:
                        end = len(cookie)
                    AUTH_TOKEN = cookie[start:end]
                    return True
            # Fallback: try reading response body for token
            body = json.loads(resp.read().decode())
            if "token" in body:
                AUTH_TOKEN = body["token"]
                return True
        return False
    except Exception as e:
        print(f"[alert] Login failed: {e}")
        return False

def lookup_device(ip: str) -> Optional[dict]:
    """Query the server for device info by IP. Returns dict with deviceId, deviceType, etc."""
    with _device_cache_lock:
        if ip in _device_cache:
            return _device_cache[ip]
    if not API_BASE:
        return None
    try:
        req = urllib.request.Request(f"{API_BASE}/api/devices")
        if AUTH_TOKEN:
            req.add_header("Cookie", f"iotscanner_token={AUTH_TOKEN}")
        opener = urllib.request.build_opener(_RedirectHandler)
        with opener.open(req, timeout=10) as resp:
            devices = json.loads(resp.read().decode())
            if isinstance(devices, list):
                for device in devices:
                    if device.get("ipAddress") == ip:
                        entry = {
                            "deviceId": device.get("deviceId"),
                            "deviceType": device.get("deviceType", "Unknown"),
                            "hostname": device.get("hostname", ""),
                            "vendor": device.get("vendor", ""),
                        }
                        with _device_cache_lock:
                            _device_cache[ip] = entry
                        return entry
    except Exception as e:
        print(f"[alert] Device lookup failed for {ip}: {e}")
    return None

def push_alert(alert_type: str, severity: str, message: str,
               device_id: int = None, src_ip: str = None, dst_ip: str = None,
               signature_id: int = None):
    if not API_BASE:
        return

    alert = {
        "alertType": alert_type,
        "severity": severity,
        "message": message,
        "deviceId": device_id,
        "srcIp": src_ip,
        "dstIp": dst_ip,
        "signatureId": signature_id,
        "timestamp": time.time(),
    }

    with _batch_lock:
        _batch.append(alert)

    _schedule_flush()

def _schedule_flush():
    global _flush_timer
    if _flush_timer is None or not _flush_timer.is_alive():
        _flush_timer = threading.Timer(2.0, _flush_batch)
        _flush_timer.daemon = True
        _flush_timer.start()

def _flush_batch():
    with _batch_lock:
        if not _batch:
            return
        batch = list(_batch)
        _batch.clear()

    try:
        payload = json.dumps({"alerts": batch}).encode()
        req = urllib.request.Request(
            f"{API_BASE}/api/alerts",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Cookie": f"iotscanner_token={AUTH_TOKEN}",
            },
            method="POST",
        )
        opener = urllib.request.build_opener(_RedirectHandler)
        with opener.open(req, timeout=15) as resp:
            body = resp.read().decode()
            print(f"[alert] Sent {len(batch)} alerts — {resp.status}")
    except Exception as e:
        print(f"[alert] Failed to send batch ({len(batch)} alerts): {e}")
        with _batch_lock:
            _batch.extendleft(reversed(batch))

def send_detection(anomalies: list[dict], device_id: int = None,
                   src_ip: str = None, dst_ip: str = None):
    for a in anomalies:
        push_alert(
            alert_type=a.get("type", "anomaly"),
            severity=a.get("severity", "Low"),
            message=a.get("detail", ""),
            device_id=device_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )

def send_rule_alert(rule_msg: str, severity: str, src_ip: str, dst_ip: str,
                    dst_port: int, device_id: int = None):
    push_alert(
        alert_type="signature_match",
        severity=severity,
        message=f"[{rule_msg}] {src_ip} -> {dst_ip}:{dst_port}",
        device_id=device_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )
