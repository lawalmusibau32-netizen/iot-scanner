"""
Behavioral anomaly detection for IoT devices.
Establishes per-device baselines and flags outliers.
"""
import time
import statistics
from collections import defaultdict, deque
from typing import Any

class DeviceBaseline:
    def __init__(self, mac: str, ip: str, device_type: str = "Unknown"):
        self.mac = mac
        self.ip = ip
        self.device_type = device_type

        self.packet_counts = deque(maxlen=60)
        self.bytes_per_window = deque(maxlen=60)
        self.dest_ips = deque(maxlen=500)
        self.dest_ports = deque(maxlen=500)
        self.hourly_volume = defaultdict(int)

        self.first_seen = time.time()
        self.last_seen = time.time()
        self.bytes_sent = 0
        self.packets_sent = 0
        self.established_dests: set[str] = set()
        self.established_ports: set[int] = set()
        self.learning_duration = 300
        self.is_learning = True
        self.learning_start = time.time()

    def observe(self, src_ip: str, dst_ip: str, dst_port: int, length: int):
        now = time.time()
        self.last_seen = now
        self.bytes_sent += length
        self.packets_sent += 1
        self.packet_counts.append(1)
        self.bytes_per_window.append(length)
        self.dest_ips.append(dst_ip)
        self.dest_ports.append(dst_port)
        self.hourly_volume[now // 3600] += length

        self.is_learning = (now - self.learning_start) < self.learning_duration

    def get_anomalies(self, dst_ip: str, dst_port: int, length: int) -> list[dict]:
        anomalies = []

        if self.is_learning:
            self.established_dests.add(dst_ip)
            self.established_ports.add(dst_port)
            return anomalies

        if dst_ip not in self.established_dests:
            anomalies.append({
                "type": "unseen_destination",
                "severity": "Medium",
                "detail": f"Device connecting to new destination {dst_ip} (port {dst_port})",
            })

        if dst_port not in self.established_ports and dst_port not in (53, 80, 443):
            anomalies.append({
                "type": "unusual_port",
                "severity": "Medium",
                "detail": f"Device using unusual port {dst_port} to {dst_ip}",
            })

        recent_dests = len(set(self.dest_ips))
        if recent_dests > 20 and self.device_type != "Router":
            anomalies.append({
                "type": "connection_spray",
                "severity": "High",
                "detail": f"Device connected to {recent_dests} unique destinations in window (possible scanning)",
            })

        if len(self.packet_counts) >= 10:
            avg_bytes = statistics.mean(self.bytes_per_window) if len(self.bytes_per_window) > 1 else length
            if length > avg_bytes * 5 and length > 50000:
                anomalies.append({
                    "type": "data_burst",
                    "severity": "High" if length > 200000 else "Medium",
                    "detail": f"Data burst: {length} bytes (avg {avg_bytes:.0f}, {length/avg_bytes:.1f}x normal)",
                })

        window = 60
        recent_packets = len([ts for ts in self.packet_counts if ts > 0])
        if recent_packets > 200 and self.device_type in ("Thermostat", "Smart Plug", "Light", "Speaker"):
            anomalies.append({
                "type": "high_throughput",
                "severity": "Medium",
                "detail": f"Device unusually active: {recent_packets} packets/min for {self.device_type}",
            })

        return anomalies


class AnomalyEngine:
    def __init__(self):
        self.devices: dict[str, DeviceBaseline] = {}
        self.global_packet_count = 0
        self.global_traffic_log = deque(maxlen=10000)

    def get_or_create_device(self, mac: str, ip: str, device_type: str = "Unknown") -> DeviceBaseline:
        if mac not in self.devices:
            self.devices[mac] = DeviceBaseline(mac, ip, device_type)
        return self.devices[mac]

    def analyze_packet(self, src_mac: str, src_ip: str, dst_ip: str,
                       dst_port: int, length: int, device_type: str = "Unknown") -> list[dict]:
        device = self.get_or_create_device(src_mac, src_ip, device_type)
        device.observe(src_ip, dst_ip, dst_port, length)
        self.global_packet_count += 1
        self.global_traffic_log.append({
            "time": time.time(), "src": src_ip, "dst": dst_ip,
            "port": dst_port, "len": length,
        })
        return device.get_anomalies(dst_ip, dst_port, length)

    def get_network_summary(self) -> dict:
        return {
            "total_devices": len(self.devices),
            "total_packets": self.global_packet_count,
            "learning_devices": sum(1 for d in self.devices.values() if d.is_learning),
            "tracked_devices": [
                {
                    "mac": d.mac, "ip": d.ip, "type": d.device_type,
                    "packets": d.packets_sent, "bytes": d.bytes_sent,
                    "learning": d.is_learning, "last_seen": time.time() - d.last_seen,
                    "destinations": len(d.established_dests),
                } for d in self.devices.values()
            ],
        }
