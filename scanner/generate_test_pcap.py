#!/usr/bin/env python3
"""Generate a test pcap with IoT/medical protocol traffic + malicious patterns."""
from scapy.all import *
import struct
import os

OUTPUT = os.path.join(os.path.dirname(__file__), "test_iot.pcap")

HOME_NET = "192.168.1."
EXTERNAL = "203.0.113."

packets = []

def ip_id():
    for i in range(1, 100000):
        yield i
_id_gen = ip_id()

def tcp_pkt(src, sport, dst, dport, payload, flags="PA"):
    ip = IP(src=src, dst=dst, id=next(_id_gen))
    tcp = TCP(sport=sport, dport=dport, flags=flags)
    pkt = Ether() / ip / tcp / Raw(load=payload)
    del pkt[IP].chksum
    del pkt[TCP].chksum
    return pkt

def udp_pkt(src, sport, dst, dport, payload):
    ip = IP(src=src, dst=dst, id=next(_id_gen))
    udp = UDP(sport=sport, dport=dport)
    pkt = Ether() / ip / udp / Raw(load=payload)
    del pkt[IP].chksum
    del pkt[UDP].chksum
    return pkt

# ── Legitimate IoT traffic ─────────────────────────────────

# MQTT: thermostat publishing temperature
packets.append(tcp_pkt(f"{HOME_NET}10", 49152, f"{EXTERNAL}1", 1883,
    b"\x10\x0e\x00\x04MQTT\x04\x02\x00\x3c\x00\x04temp1"))  # CONNECT
packets.append(tcp_pkt(f"{HOME_NET}10", 49153, f"{EXTERNAL}1", 1883,
    b"\x30\x15\x00\x0btemperature\x7b\x22temp\x22\x3a\x32\x32\x2e\x35\x7d"))  # PUBLISH

# MQTT: smart plug subscribing
packets.append(tcp_pkt(f"{HOME_NET}11", 49154, f"{EXTERNAL}1", 1883,
    b"\x10\x0d\x00\x04MQTT\x04\x02\x00\x3c\x00\x03plg1"))  # CONNECT
packets.append(tcp_pkt(f"{HOME_NET}11", 49155, f"{EXTERNAL}1", 1883,
    b"\x82\x0a\x00\x01\x00\x09power/cmd"))  # SUBSCRIBE

# CoAP: sensor reading
packets.append(udp_pkt(f"{HOME_NET}12", 5683, f"{EXTERNAL}2", 5683,
    b"\x40\x01\x00\x01\xb9temp"))  # CON GET

# HL7: medical device sending patient data
hl7_msg = b"MSH|^~\\&|ICU_MON|HOSP|EHR|HOSP|202403011200||ADT^A01|MSG001|P|2.5\rPID|||PAT001||DOE^JOHN||19700101|M"
packets.append(tcp_pkt(f"{HOME_NET}20", 5000, f"{EXTERNAL}3", 2575, hl7_msg))

# DICOM: imaging device
dicom_msg = b"DICOM\x10\x00\x00\x00PATIENT^DOE^JANE^^^^STUDY^CT_CHEST"
packets.append(tcp_pkt(f"{HOME_NET}21", 5001, f"{EXTERNAL}4", 2760, dicom_msg))

# ── Malicious traffic ─────────────────────────────────────

# Mirai: HTTP scan from infected IoT device
packets.append(tcp_pkt(f"{HOME_NET}50", 40000, f"{EXTERNAL}10", 80,
    b"GET /scan HTTP/1.1\r\nHost: 203.0.113.10\r\n\r\n"))

# Mirai: Telnet brute force targets receiving "root"/"admin"
packets.append(tcp_pkt(f"{EXTERNAL}20", 31337, f"{HOME_NET}50", 23, b"root\r\n"))
packets.append(tcp_pkt(f"{EXTERNAL}20", 31338, f"{HOME_NET}50", 23, b"admin\r\n"))

# SSH brute force: 15 attempts to trigger detection_filter (count 10, seconds 30)
for i in range(15):
    packets.append(tcp_pkt(f"{EXTERNAL}30", 50000 + i, f"{HOME_NET}51", 22,
        b"SSH-2.0-OpenSSH_8.9\r\n"))

# Connection spray: IoT device talking to 35 unique destinations
for i in range(35):
    packets.append(tcp_pkt(f"{HOME_NET}52", 60000 + i, f"{EXTERNAL}{100+i}", 80,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

# Data burst: thermostat sending large payload (multiple segments)
burst_payload = b"X" * 65000
for i in range(4):
    packets.append(tcp_pkt(f"{HOME_NET}10", 49156 + i, f"{EXTERNAL}1", 8883, burst_payload))

# NTP amplification: infected device sending many NTP queries (trigger count 100, seconds 5)
for i in range(150):
    packets.append(udp_pkt(f"{HOME_NET}53", 123, f"{EXTERNAL}50", 123,
        b"\x1b" + b"\x00" * 47))

# Mirai CNC beacon
packets.append(tcp_pkt(f"{HOME_NET}50", 40001, f"{EXTERNAL}10", 48101,
    b"\x00\x00\x00\x00\x01\x02\x03\x04"))

# mDNS reflection: 60 packets to trigger count 50, seconds 5
for i in range(60):
    packets.append(udp_pkt(f"{EXTERNAL}60", 5353, f"{HOME_NET}54", 5353,
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"))

print(f"[gen] Writing {len(packets)} packets to {OUTPUT}")
wrpcap(OUTPUT, packets)
print(f"[gen] Done — {os.path.getsize(OUTPUT)} bytes")
