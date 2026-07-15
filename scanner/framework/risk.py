"""
Module 4: Risk Analysis Engine
Calculates risk scores based on CVSS-like methodology:
  Risk = Likelihood × Impact / 10
Evaluates exploitability, attack vector, and potential damage.
"""
from .models import Vulnerability, RiskAssessment, Device


LIKELIHOOD_FACTORS = {
    "exploitability": {
        "telnet": 9.0, "ftp": 7.0, "http": 6.0, "snmp": 8.0,
        "upnp": 7.0, "smb": 8.0, "rdp": 8.0, "ssh": 5.0,
        "mqtt": 6.0, "coap": 5.0,
    },
    "default_weight": 5.0,
    "auth_required": 0.7,      # multiplier if auth required
    "network_reachable": 0.9,  # multiplier if LAN-only
}

IMPACT_FACTORS = {
    "confidentiality": {
        "ftp": 7.0, "http": 5.0, "snmp": 6.0, "smb": 8.0,
        "telnet": 6.0, "rdp": 8.0, "mqtt": 6.0,
    },
    "integrity": {
        "ftp": 6.0, "http": 5.0, "telnet": 7.0, "smb": 7.0,
        "mqtt": 7.0,
    },
    "availability": {
        "upnp": 9.0, "smb": 7.0, "telnet": 5.0, "rdp": 6.0,
    },
    "default_weight": 5.0,
}


def calculate(vulnerabilities: list[Vulnerability], device: Device) -> list[RiskAssessment]:
    """Calculate risk scores for each vulnerability using likelihood × impact model."""
    assessments = []
    device_type = device.device_type

    for vuln in vulnerabilities:
        service = vuln.affected_service or "unknown"
        service_lower = service.split("/")[0]  # take first service if multiple

        # Likelihood calculation
        exploit_base = LIKELIHOOD_FACTORS["exploitability"].get(service_lower,
                         LIKELIHOOD_FACTORS["default_weight"])

        # Adjust for device type (certain devices are more targeted)
        if device_type in ("Router", "Camera", "NAS") and service_lower in ("http", "ssh"):
            exploit_base = min(exploit_base + 1.0, 10.0)

        # Impact calculation
        conf = IMPACT_FACTORS["confidentiality"].get(service_lower,
                IMPACT_FACTORS["default_weight"])
        integ = IMPACT_FACTORS["integrity"].get(service_lower,
                IMPACT_FACTORS["default_weight"])
        avail = IMPACT_FACTORS["availability"].get(service_lower,
                IMPACT_FACTORS["default_weight"])

        # Average impact across CIA triad
        impact = (conf + integ + avail) / 3

        # Apply modifier from CVSS score
        if vuln.cvss_score > 0:
            cvss_modifier = vuln.cvss_score / 10.0
            impact = impact * (0.5 + cvss_modifier * 0.5)
            exploit_base = exploit_base * (0.5 + cvss_modifier * 0.5)

        # For CVE-tagged vulns, use the CVSS score directly
        if vuln.cve_id.startswith("CVE-"):
            risk_score = vuln.cvss_score
        else:
            risk_score = round((exploit_base * impact) / 10, 1)
            risk_score = min(risk_score, 10.0)

        severity = Vulnerability.classify_severity(risk_score)

        factors = {
            "exploitability": round(exploit_base, 1),
            "confidentiality_impact": round(conf, 1),
            "integrity_impact": round(integ, 1),
            "availability_impact": round(avail, 1),
            "impact_score": round(impact, 1),
            "device_type": device_type,
            "service": service_lower,
        }

        assessments.append(RiskAssessment(
            device_ip=vuln.device_ip,
            cve_id=vuln.cve_id,
            vulnerability=vuln.description[:80],
            likelihood=round(exploit_base / 10, 2),
            impact=round(impact / 10, 2),
            risk_score=risk_score,
            severity=severity,
            factors=factors,
        ))

    return assessments
