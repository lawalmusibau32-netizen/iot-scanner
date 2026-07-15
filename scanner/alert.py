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

API_BASE = None
AUTH_TOKEN = None

_batch = deque(maxlen=500)
_batch_lock = threading.Lock()
_flush_timer: Optional[threading.Timer] = None

def configure(api_base: str, auth_token: str):
    global API_BASE, AUTH_TOKEN
    API_BASE = api_base
    AUTH_TOKEN = auth_token

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
        urllib.request.urlopen(req, timeout=10)
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
