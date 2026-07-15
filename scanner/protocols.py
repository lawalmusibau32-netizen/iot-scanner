"""
Protocol dissectors for IoT/medical device traffic.
Detects application-layer protocols in raw packets.
"""
import struct
import socket
from typing import Optional

PORT_PROTOCOL_MAP = {
    1883: "MQTT", 8883: "MQTT_TLS", 5683: "CoAP", 5684: "CoAP_DTLS",
    2760: "DICOM", 2575: "HL7", 5060: "SIP", 5061: "SIP_TLS",
    4840: "OPC_UA", 4843: "OPC_UA_TLS", 161: "SNMP", 162: "SNMP_TRAP",
    514: "SYSLOG", 6514: "SYSLOG_TLS",
}

def detect_protocol(payload: bytes, sport: int, dport: int) -> Optional[dict]:
    proto = PORT_PROTOCOL_MAP.get(dport) or PORT_PROTOCOL_MAP.get(sport)
    dissector = {
        "MQTT": _dissect_mqtt,
        "CoAP": _dissect_coap,
        "DICOM": _dissect_dicom,
        "HL7": _dissect_hl7,
        "SIP": _dissect_sip,
    }.get(proto)

    if not proto:
        proto = _heuristic_protocol(payload)

    return {
        "protocol": proto,
        "details": dissector(payload) if dissector else {},
    }

def _heuristic_protocol(payload: bytes) -> Optional[str]:
    if payload[:4] == b"\x10\x00\x00\x00" or payload[:1] == b"\x10":
        return "MQTT"
    if b"MSH|" in payload or b"QRY|" in payload or b"PID|" in payload:
        return "HL7"
    if b"DICOM" in payload or b"PATIENT" in payload:
        return "DICOM"
    if payload[:1] == b"\x40" or payload[:1] == b"\x60":
        return "CoAP"
    if b"INVITE" in payload or b"REGISTER" in payload or b"SIP/2.0" in payload:
        return "SIP"
    if b"GET /" in payload or b"POST /" in payload or b"HTTP/" in payload:
        return "HTTP"
    return None

def _dissect_mqtt(payload: bytes) -> dict:
    if not payload:
        return {}
    msg_type = (payload[0] >> 4) & 0x0F
    types = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
             8: "SUBSCRIBE", 9: "SUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT"}
    result = {"type": types.get(msg_type, f"UNKNOWN_{msg_type}")}
    if msg_type == 3 and len(payload) > 2:
        remaining = payload[1] & 0x7F
        pos = 2
        topic_len = struct.unpack("!H", payload[pos:pos+2])[0]
        topic = payload[pos+2:pos+2+topic_len].decode("utf-8", errors="replace")
        result["topic"] = topic
        if len(payload) > pos + 2 + topic_len:
            raw = payload[pos+2+topic_len:]
            result["has_payload"] = bool(raw.strip(b"\x00"))
            result["payload_snippet"] = raw[:100].decode("utf-8", errors="replace")
    return result

def _dissect_coap(payload: bytes) -> dict:
    if not payload or len(payload) < 4:
        return {}
    ver = (payload[0] >> 6) & 0x03
    msg_type = (payload[0] >> 4) & 0x03
    code = payload[1]
    msg_id = struct.unpack("!H", payload[2:4])[0]
    codes = {0.01: "GET", 0.02: "POST", 0.03: "PUT", 0.04: "DELETE",
             2.01: "2.01 Created", 2.05: "2.05 Content", 4.00: "4.00 Bad Request",
             4.04: "4.04 Not Found", 4.05: "4.05 Method Not Allowed", 5.00: "5.00 Internal"}
    code_float = code / 100.0
    return {
        "version": ver, "type": ["CON", "NON", "ACK", "RST"][msg_type],
        "code": codes.get(code_float, f"{code_float:.2f}"), "msg_id": msg_id,
    }

def _dissect_dicom(payload: bytes) -> dict:
    if not payload:
        return {}
    result = {}
    text = payload.decode("utf-8", errors="replace")
    for keyword in ["PATIENT", "STUDY", "SERIES", "IMAGE", "DICOM"]:
        if keyword in text:
            result[keyword.lower()] = True
    idx = text.find("PATIENT")
    if idx != -1:
        result["patient_snippet"] = text[idx:idx+80]
    return result

def _dissect_hl7(payload: bytes) -> dict:
    if not payload:
        return {}
    segments = {}
    text = payload.decode("utf-8", errors="replace")
    for line in text.split("\r"):
        line = line.strip()
        if not line:
            continue
        seg_id = line[:3]
        fields = line.split("|")
        if seg_id == "MSH":
            segments["message_type"] = fields[8] if len(fields) > 8 else ""
            segments["sending_app"] = fields[2] if len(fields) > 2 else ""
        elif seg_id == "PID":
            segments["contains_patient_id"] = True
            segments["patient_name"] = fields[5] if len(fields) > 5 else ""
        elif seg_id == "QRY":
            segments["query"] = True
        elif seg_id == "OBX":
            segments["observation"] = True
    return segments

def _dissect_sip(payload: bytes) -> dict:
    if not payload:
        return {}
    text = payload.decode("utf-8", errors="replace")
    result = {}
    first_line = text.split("\r\n")[0] if "\r\n" in text else text.split("\n")[0]
    if "INVITE" in first_line:
        result["method"] = "INVITE"
    elif "REGISTER" in first_line:
        result["method"] = "REGISTER"
    elif "BYE" in first_line:
        result["method"] = "BYE"
    if "sip:" in text:
        start = text.find("sip:")
        end = text.find(" ", start) if text.find(" ", start) != -1 else text.find("\r\n", start)
        if end == -1:
            end = len(text)
        result["uri"] = text[start:end]
    return result
