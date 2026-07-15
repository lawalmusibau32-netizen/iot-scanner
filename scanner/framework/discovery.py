"""
Module 1: Network Discovery
Discovers all IoT devices connected to the residential network.
Uses ARP scanning, ping sweep, and mDNS discovery.
"""
import ipaddress
import subprocess
import sys
import socket
import re
from typing import Optional
from .models import Device


def discover(network: str = "192.168.1.0/24", timeout: int = 15) -> list[Device]:
    """Discover all devices on the network. Returns list of Device objects with basic info."""
    devices = []

    # Phase 1: ARP scan
    arp_devices = _arp_scan(timeout=timeout)
    devices.extend(arp_devices)

    # Phase 2: Ping sweep for non-ARP devices
    seen_ips = {d.ip for d in devices}
    pinged = _ping_sweep(network, timeout=timeout)
    for ip in pinged:
        if ip not in seen_ips:
            mac = _resolve_mac(ip)
            devices.append(Device(ip=ip, mac=mac or "", hostname=_resolve_hostname(ip)))
            seen_ips.add(ip)

    # Phase 3: mDNS discovery for local hostnames
    _mdns_discover(devices)

    return devices


def _arp_scan(timeout: int = 10) -> list[Device]:
    """ARP scan using system ARP table."""
    devices = []
    try:
        if sys.platform == "win32":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=timeout)
            for line in result.stdout.split("\n"):
                parts = line.strip().split()
                if len(parts) >= 3 and _is_valid_mac(parts[1]):
                    ip = parts[0].strip("()")
                    mac = parts[1].replace("-", ":")
                    devices.append(Device(ip=ip, mac=mac, hostname=_resolve_hostname(ip)))
        else:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=timeout)
            for line in result.stdout.split("\n"):
                parts = line.strip().split()
                if len(parts) >= 4 and _is_valid_mac(parts[2]):
                    devices.append(Device(
                        ip=parts[0],
                        mac=parts[2],
                        hostname=parts[1] if parts[1] != "(incomplete)" else "",
                    ))
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[discovery] ARP scan error: {e}")
    return devices


def _ping_sweep(network: str, timeout: int = 10) -> list[str]:
    """Quick ping sweep to find responsive hosts."""
    found = []
    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())[:254]
        for ip in hosts:
            ip_str = str(ip)
            if sys.platform == "win32":
                cmd = ["ping", "-n", "1", "-w", "500", ip_str]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip_str]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                if r.returncode == 0:
                    found.append(ip_str)
            except subprocess.TimeoutExpired:
                continue
    except Exception as e:
        print(f"[discovery] Ping sweep error: {e}")
    return found


def _mdns_discover(devices: list[Device]):
    """Resolve mDNS hostnames for discovered devices."""
    for dev in devices:
        if not dev.hostname:
            try:
                hostname, _, _ = socket.gethostbyaddr(dev.ip)
                dev.hostname = hostname
            except (socket.herror, socket.gaierror):
                # Try mDNS resolution
                try:
                    mdns_name = f"{dev.ip.replace('.', '-')}.local"
                    hostname, _, _ = socket.gethostbyname_ex(mdns_name)
                    if hostname:
                        dev.hostname = hostname
                except Exception:
                    pass


def _resolve_hostname(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


def _resolve_mac(ip: str) -> str:
    """Resolve MAC address for an IP using ARP table."""
    try:
        if sys.platform == "win32":
            result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split("\n"):
                if ip in line:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        return parts[1].replace("-", ":")
        else:
            result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split("\n"):
                if ip in line:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        return parts[2]
    except Exception:
        pass
    return ""


def _is_valid_mac(mac: str) -> bool:
    cleaned = mac.replace(":", "").replace("-", "").lower()
    return len(cleaned) == 12 and all(c in "0123456789abcdef" for c in cleaned)
