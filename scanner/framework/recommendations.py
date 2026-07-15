"""
Module 5: Recommendation Engine
Generates prioritized security recommendations per vulnerability and device.
"""
from .models import Vulnerability, RiskAssessment, Recommendation, Device

RECOMMENDATION_TEMPLATES = {
    "credentials": {
        "description": "Weak or default credentials detected on {device}",
        "action": "Change the default username and password. Use a password manager to generate and store a strong unique password (min 12 characters, mixed case + numbers + symbols). Enable multi-factor authentication if supported.",
        "priority": "High",
    },
    "encryption": {
        "description": "Unencrypted communication protocol detected on {device}",
        "action": "Replace {service} with its encrypted equivalent. Enable TLS/SSL wherever possible. If encryption is not supported, isolate the device on a separate VLAN.",
        "priority": "High",
    },
    "network": {
        "description": "Network exposure risk on {device}",
        "action": "Restrict access to {service} by source IP using firewall rules. If the service is not required, disable it. Consider network segmentation for IoT devices.",
        "priority": "Medium",
    },
    "firmware": {
        "description": "Firmware/software update needed on {device}",
        "action": "Check the manufacturer's support website for the latest firmware version. Apply updates following vendor instructions. Enable automatic updates if available.",
        "priority": "High",
    },
    "config": {
        "description": "Security configuration issue on {device}",
        "action": "Review device security settings. Disable unnecessary features and services. Enable logging and monitoring if available.",
        "priority": "Medium",
    },
    "replacement": {
        "description": "Device {device} may need replacement",
        "action": "This device appears to be end-of-life or unsupported. Replace with a current model that receives regular security updates. Check the manufacturer's support lifecycle page.",
        "priority": "Medium",
    },
}


def generate(device: Device, vulnerabilities: list[Vulnerability],
             risk_assessments: list[RiskAssessment]) -> list[Recommendation]:
    """Generate prioritized security recommendations."""
    recommendations = []
    device_name = device.hostname or device.ip
    seen_categories = set()

    # Group risk assessments by CVE for priority
    risk_by_cve = {}
    for ra in risk_assessments:
        if ra.cve_id not in risk_by_cve or ra.risk_score > risk_by_cve[ra.cve_id].risk_score:
            risk_by_cve[ra.cve_id] = ra

    for vuln in vulnerabilities:
        # Determine category from CVE ID prefix or affected service
        category = _categorize_vuln(vuln)
        if category in seen_categories:
            continue
        seen_categories.add(category)

        template = RECOMMENDATION_TEMPLATES.get(category, RECOMMENDATION_TEMPLATES["config"])
        risk = risk_by_cve.get(vuln.cve_id)

        # Determine priority from risk score
        if risk:
            if risk.risk_score >= 6.1:
                priority = "High"
            elif risk.risk_score >= 4.1:
                priority = "Medium"
            else:
                priority = "Low"
        else:
            priority = template["priority"]

        action = template["action"].format(
            device=device_name,
            service=vuln.affected_service or "the affected service",
        )

        recommendations.append(Recommendation(
            device_ip=device.ip,
            device_name=device_name,
            category=category,
            priority=priority,
            description=template["description"].format(device=device_name),
            action=action,
            cve_id=vuln.cve_id,
        ))

    # Add device-level recommendations if too many open ports
    if len(device.open_ports) > 8:
        recommendations.append(Recommendation(
            device_ip=device.ip,
            device_name=device_name,
            category="network",
            priority="Medium",
            description=f"Device {device_name} has {len(device.open_ports)} open ports — reduce attack surface",
            action="Audit all open ports and close unnecessary ones. Use a firewall to restrict access to required ports only. Consider moving the device to an isolated VLAN.",
        ))

    # Add network segmentation recommendation for IoT devices
    if device.device_type in ("Camera", "Smart Plug", "Light", "IoT Sensor", "Thermostat"):
        recommendations.append(Recommendation(
            device_ip=device.ip,
            device_name=device_name,
            category="network",
            priority="Low",
            description=f"Consider network segmentation for {device_name} ({device.device_type})",
            action="Place IoT devices on a separate VLAN/subnet isolated from critical devices (computers, phones, NAS). Use firewall rules to restrict IoT device access to only necessary external services.",
        ))

    return recommendations


def _categorize_vuln(vuln: Vulnerability) -> str:
    """Map a vulnerability to a recommendation category."""
    cve = vuln.cve_id
    service = (vuln.affected_service or "").lower()

    if "default" in cve.lower() or "cred" in cve.lower():
        return "credentials"
    if "tls" in service or "ssl" in service:
        return "encryption"
    if cve.startswith("CFG-FIRMWARE") or cve.startswith("CFG-DEVICE-EOL"):
        return "replacement" if "EOL" in cve else "firmware"
    if cve.startswith("CVE-"):
        return "firmware"
    if "upnp" in service or "smb" in service or "rdp" in service:
        return "network"
    if "telnet" in service or "ftp" in service:
        return "encryption"
    if "mqtt" in service or "coap" in service:
        return "encryption"
    if "http" in service:
        return "encryption"
    if "snmp" in service:
        return "credentials"
    if "unnecessary" in cve.lower() or "multiple" in cve.lower():
        return "config"

    return "config"
