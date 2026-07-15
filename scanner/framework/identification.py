"""
Module 2: Device Identification
Fingerprints devices to determine manufacturer, device type, OS, firmware, and services.
"""
import socket
import subprocess
import sys
import re
from typing import Optional
from .models import Device, Port


# MAC OUI → Manufacturer lookup (common prefixes for IoT devices)
OUI_MAP = {
    "00:0a:95": "TP-Link Technologies",
    "00:1a:79": "TP-Link Technologies",
    "14:cf:92": "TP-Link Technologies",
    "50:c7:bf": "TP-Link Technologies",
    "b0:be:76": "TP-Link Technologies",
    "e8:48:b8": "TP-Link Technologies",
    "d0:95:a6": "TP-Link Technologies",
    "f4:f2:6d": "TP-Link Technologies",
    "48:f8:b3": "TP-Link Technologies",
    "ac:84:c6": "TP-Link Technologies",
    "0c:72:2c": "Intel Corporation",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:1b:21": "Cisco Systems",
    "70:30:5e": "D-Link International",
    "00:0d:88": "D-Link International",
    "28:10:7b": "D-Link International",
    "34:08:04": "Huawei Technologies",
    "f8:c3:9e": "Huawei Technologies",
    "c0:ee:fb": "Huawei Technologies",
    "20:df:b9": "Samsung Electronics",
    "8c:45:00": "Samsung Electronics",
    "a4:77:33": "Samsung Electronics",
    "00:17:88": "Apple",
    "3c:22:fb": "Apple",
    "b8:09:8a": "Apple",
    "ac:bc:32": "Apple",
    "00:0f:53": "Sonos",
    "94:10:3e": "Sonos",
    "b8:27:eb": "Raspberry Pi",
    "8c:ae:4c": "Google Nest",
    "18:b4:30": "Google Nest",
    "b4:79:a7": "Google Nest",
    "a4:77:33": "Samsung",
    "e0:76:d0": "Amazon Technologies",
    "74:c2:46": "Amazon Technologies",
    "8c:85:90": "Ring (Amazon)",
    "b0:fc:36": "Ring (Amazon)",
    "00:1e:13": "NETGEAR",
    "24:b6:fd": "NETGEAR",
    "6c:b0:ce": "NETGEAR",
    "a0:21:b7": "NETGEAR",
    "c0:3f:0e": "NETGEAR",
    "00:9a:9a": "Xiaomi Communications",
    "8c:de:52": "Xiaomi Communications",
    "f4:6b:ef": "Xiaomi Communications",
    "00:22:6b": "ASUSTek Computer",
    "10:fe:ed": "ASUSTek Computer",
    "14:cc:20": "ASUSTek Computer",
    "50:c7:bf": "ASUSTek Computer",
    "68:7f:74": "ASUSTek Computer",
    "84:25:db": "ASUSTek Computer",
    "88:d7:f6": "ASUSTek Computer",
    "e0:3f:49": "ASUSTek Computer",
    "e8:40:f2": "ASUSTek Computer",
    "18:31:bf": "Belkin International",
    "94:44:52": "Belkin International",
    "00:14:d1": "Philips (Hue)",
    "ec:b5:fa": "Philips (Hue)",
    "00:17:88": "Apple",
    "f0:9f:c2": "Apple",
    "00:24:36": "Xerox",
    "00:0f:55": "Epson",
    "00:12:17": "Hewlett Packard",
    "00:1e:c5": "Hewlett Packard",
    "00:26:ab": "Hewlett Packard",
    "00:0b:82": "Canon",
    "00:1e:e1": "Canon",
    "08:00:46": "Motorola",
    "00:15:6d": "Roku",
    "00:0d:4f": "Sonos",
    "00:16:3e": "Xen",
}

# Quick reachability check
def _is_reachable(ip: str) -> bool:
    """Quick check if a device is reachable before port scanning."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        # Try connecting to port 1 (just to see if host is up)
        result = s.connect_ex((ip, 1))
        s.close()
        return result == 0
    except Exception:
        return False


# Port → Device type heuristics
PORT_DEVICE_CLASSES = {
    (80, 443, 8080): "Router",
    (80, 443, 23): "Router",
    (80, 23, 21): "Camera",
    (554, 8554): "Camera",
    (53, 67, 68): "Router",
    (1883, 8883): "IoT Sensor",
    (5683, 5684): "IoT Sensor",
    (5353,): "Media Device",
    (139, 445): "NAS",
    (548,): "NAS",
    (2049,): "NAS",
    (5900,): "Desktop",
    (3389,): "Desktop",
    (22,): "Desktop",
}


def identify(device: Device, port_range: str = "common") -> Device:
    """Fingerprint a device: manufacturer, open ports, services, device type."""
    # Step 1: Manufacturer from MAC OUI
    if device.mac:
        oui = _oui_from_mac(device.mac)
        if oui:
            device.manufacturer = oui

    # Quick reachability check before scanning
    if not _is_reachable(device.ip):
        return device

    # Step 2: Port scan
    open_ports = []
    for port in ports_to_scan:
        result = _check_port(device.ip, port)
        if result:
            open_ports.append(result)

    device.open_ports = open_ports
    device.services = {str(p.number): p.service for p in open_ports}

    # Step 3: Banner grab for service versions
    for p in open_ports:
        banner = _grab_banner(device.ip, p.number)
        if banner:
            p.banner = banner[:200]

    # Step 4: OS fingerprint via TTL
    os_name, os_ver = _fingerprint_os(device.ip)
    device.os_name = os_name
    device.os_version = os_ver

    # Step 5: Firmware detection from HTTP banners
    for p in open_ports:
        if p.service in ("http", "https") and "Server:" in p.banner:
            match = re.search(r'Server:\s*([^\r\n]+)', p.banner)
            if match:
                server = match.group(1)
                # Extract firmware version from server header
                ver_match = re.search(r'[\d]+\.[\d]+\.[\d]+', server)
                if ver_match:
                    device.firmware_version = ver_match.group()
                    break

    # Step 6: Device type classification
    device.device_type = _classify_device(device)

    return device


def _oui_from_mac(mac: str) -> str:
    """Look up manufacturer from MAC OUI prefix."""
    normalized = mac.upper().replace("-", ":")
    parts = normalized.split(":")
    if len(parts) < 3:
        return ""
    oui = ":".join(parts[:3])
    return OUI_MAP.get(oui, OUI_MAP.get(oui[:8], ""))


def _get_ports(port_range: str) -> list[int]:
    """Return list of ports to scan based on range selection."""
    common = [21, 22, 23, 25, 53, 80, 110, 123, 139, 143, 161, 443, 445, 514,
              548, 554, 587, 993, 995, 1433, 1521, 1723, 1883, 2049, 3306, 3389,
              5060, 5432, 5683, 5900, 6379, 8080, 8443, 8554, 8883, 9090, 27017,
              49152, 49153, 49154]
    if port_range == "quick":
        return [21, 22, 23, 53, 80, 443, 554, 1883, 8080, 8443]
    elif port_range == "full":
        extended = common + list(range(1024, 5000))
        return extended
    return common


def _check_port(ip: str, port: int, timeout: float = 0.8) -> Optional[Port]:
    """TCP connect scan to check if port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        if result == 0:
            service = _get_service_name(port)
            s.close()
            return Port(number=port, service=service)
        s.close()
    except Exception:
        pass
    return None


def _get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        services = {
            1812: "radius", 1883: "mqtt", 2056: "omniscience",
            2082: "cpanel", 2083: "radsec", 3306: "mysql",
            3389: "ms-wbt-server", 5432: "postgresql", 5672: "amqp",
            5683: "coap", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
            8443: "https-alt", 8554: "rtsp-alt", 8883: "mqtt-tls",
            27017: "mongodb", 49152: "upnp",
        }
        return services.get(port, "unknown")


def _grab_banner(ip: str, port: int, timeout: float = 3) -> str:
    """Attempt to grab a service banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Send probe for common protocols
        if port in (80, 8080, 8443):
            s.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port in (21,):
            pass  # FTP sends banner on connect
        elif port in (22,):
            pass  # SSH sends banner on connect
        elif port in (25, 587):
            pass  # SMTP sends banner on connect
        elif port in (110,):
            pass  # POP3 sends banner on connect
        elif port in (143, 993):
            pass  # IMAP sends banner on connect
        else:
            s.send(b"\r\n")
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner[:300]
    except Exception:
        return ""


def _fingerprint_os(ip: str) -> tuple[str, str]:
    """Simple OS fingerprinting based on TTL and TCP window size."""
    try:
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.settimeout(3)
        s.connect((ip, 80))
        s.send(b"\x00")
        resp = s.recv(1024)
        s.close()
        if len(resp) > 8:
            ttl = resp[8]
            if ttl <= 64:
                return "Linux/Unix", ""
            elif ttl <= 128:
                return "Windows", ""
            else:
                return "Unknown", ""
    except Exception:
        pass
    return "", ""


def _classify_device(device: Device) -> str:
    """Classify device type based on open ports, manufacturer, and hostname."""
    port_set = {p.number for p in device.open_ports}
    name_lower = (device.hostname + device.manufacturer).lower()

    # Router
    if 53 in port_set:
        return "Router"
    if 80 in port_set and 443 in port_set and 23 in port_set:
        return "Router"
    if "router" in name_lower or "gateway" in name_lower or "ap" in name_lower:
        return "Router"

    # Camera
    if 554 in port_set or 8554 in port_set:
        return "Camera"
    if 80 in port_set and 23 in port_set:
        return "Camera"
    if "camera" in name_lower or "cam" in name_lower or "ipc" in name_lower:
        return "Camera"

    # NAS / Storage
    if 139 in port_set or 445 in port_set or 548 in port_set or 2049 in port_set:
        return "NAS"
    if "nas" in name_lower or "storage" in name_lower:
        return "NAS"

    # Media / Streaming
    if 5353 in port_set:
        return "Media Device"
    if "roku" in name_lower or "firetv" in name_lower or "chromecast" in name_lower:
        return "Media Device"
    if "sonos" in name_lower or "speaker" in name_lower:
        return "Speaker"

    # Thermostat
    if "thermo" in name_lower or "nest" in name_lower or "ecobee" in name_lower:
        return "Thermostat"

    # Smart Plug
    if "plug" in name_lower or "switch" in name_lower or "tplink" in name_lower:
        return "Smart Plug"

    # Smart Light
    if "light" in name_lower or "hue" in name_lower or "bulb" in name_lower:
        return "Light"

    # Smart Lock
    if "lock" in name_lower or "smartlock" in name_lower:
        return "Smart Lock"

    # IoT Sensor
    if 1883 in port_set or 8883 in port_set or 5683 in port_set:
        return "IoT Sensor"

    # Desktop / Server
    if 3389 in port_set or 5900 in port_set:
        return "Desktop"
    if 22 in port_set and 443 in port_set:
        return "Server"

    if "raspberry" in name_lower or "rpi" in name_lower:
        return "Development Board"

    return "Other"
