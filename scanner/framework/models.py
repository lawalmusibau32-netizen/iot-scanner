"""Shared data models for the IoT vulnerability assessment framework."""
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime
import json


@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    service: str = "unknown"
    banner: str = ""
    state: str = "open"

    def to_dict(self):
        return asdict(self)


@dataclass
class Device:
    mac: str = ""
    ip: str = ""
    hostname: str = ""
    manufacturer: str = "Unknown"
    device_type: str = "Unknown"
    os_name: str = ""
    os_version: str = ""
    firmware_version: str = ""
    open_ports: list = field(default_factory=list)
    services: dict = field(default_factory=dict)
    is_active: bool = True
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self):
        d = asdict(self)
        d["open_ports"] = [p.to_dict() if isinstance(p, Port) else p for p in self.open_ports]
        return d


@dataclass
class Vulnerability:
    cve_id: str = ""
    cvss_score: float = 0.0
    severity: str = "Low"
    description: str = ""
    affected_service: str = ""
    affected_port: Optional[int] = None
    device_ip: str = ""
    evidence: str = ""

    SEVERITY_MAP = {
        (0.0, 1.0): "Low",
        (1.1, 4.0): "Low",
        (4.1, 6.0): "Medium",
        (6.1, 8.0): "High",
        (8.1, 10.0): "Critical",
    }

    @classmethod
    def classify_severity(cls, score: float) -> str:
        if score >= 8.1:
            return "Critical"
        elif score >= 6.1:
            return "High"
        elif score >= 4.1:
            return "Medium"
        return "Low"

    def to_dict(self):
        return asdict(self)


@dataclass
class RiskAssessment:
    device_ip: str = ""
    cve_id: str = ""
    vulnerability: str = ""
    likelihood: float = 0.0
    impact: float = 0.0
    risk_score: float = 0.0
    severity: str = "Low"
    factors: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class Recommendation:
    device_ip: str = ""
    device_name: str = ""
    category: str = ""  # firmware, credentials, network, encryption, config, replacement
    priority: str = "Medium"
    description: str = ""
    action: str = ""
    cve_id: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class Report:
    generated_at: str = ""
    network_cidr: str = ""
    total_devices: int = 0
    total_vulnerabilities: int = 0
    overall_risk_score: float = 0.0
    overall_severity: str = "Low"
    devices: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    risk_assessments: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    risk_summary: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent)

    def to_html(self) -> str:
        return _render_html_report(self)


SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#16a34a",
}


def _render_html_report(report: Report) -> str:
    device_rows = ""
    for d in report.devices:
        if isinstance(d, dict):
            ports_list = d.get("open_ports", [])
            ip = d.get("ip", "")
            mac = d.get("mac", "")
            mfg = d.get("manufacturer", "")
            dt = d.get("device_type", "")
        else:
            ports_list = d.open_ports
            ip = d.ip
            mac = d.mac
            mfg = d.manufacturer
            dt = d.device_type
        ports = ", ".join(str(p["number"]) if isinstance(p, dict) else str(p.number) for p in ports_list)
        device_rows += f"""<tr>
            <td>{ip}</td>
            <td>{mac}</td>
            <td>{mfg}</td>
            <td>{dt}</td>
            <td>{ports}</td>
        </tr>\n"""

    def _get(obj, key, default=""):
        return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)

    vuln_rows = ""
    for v in report.vulnerabilities:
        color = SEVERITY_COLORS.get(_get(v, "severity"), "#6b7280")
        vuln_rows += f"""<tr>
            <td>{_get(v, "cve_id")}</td>
            <td>{_get(v, "device_ip")}</td>
            <td>{_get(v, "description")}</td>
            <td style="color:{color};font-weight:600">{_get(v, "severity")}</td>
            <td>{_get(v, "cvss_score")}</td>
        </tr>\n"""

    rec_rows = ""
    for r in report.recommendations:
        color = SEVERITY_COLORS.get(_get(r, "priority"), "#6b7280")
        rec_rows += f"""<tr>
            <td>{_get(r, "device_ip")}</td>
            <td>{_get(r, "category")}</td>
            <td style="color:{color};font-weight:600">{_get(r, "priority")}</td>
            <td>{_get(r, "description")}</td>
            <td>{_get(r, "action")}</td>
        </tr>\n"""

    severity_bar = ""
    summary = report.risk_summary if isinstance(report.risk_summary, dict) else {}
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = summary.get(sev, 0)
        pct = (count / max(report.total_vulnerabilities, 1)) * 100
        color = SEVERITY_COLORS.get(sev, "#6b7280")
        if count:
            severity_bar += f"""<div style="display:flex;align-items:center;gap:8px;margin:4px 0">
                <span style="width:80px;font-size:13px">{sev}</span>
                <div style="flex:1;height:20px;background:#e5e7eb;border-radius:4px;overflow:hidden">
                    <div style="height:100%;width:{pct:.0f}%;background:{color};border-radius:4px"></div>
                </div>
                <span style="width:40px;text-align:right;font-size:13px">{count}</span>
            </div>"""

    score_color = SEVERITY_COLORS.get(report.overall_severity, "#6b7280")

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>IoT Vulnerability Assessment Report</title>
<style>
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#f8fafc; color:#1e293b; }}
    .container {{ max-width:1100px; margin:0 auto; padding:40px 20px; }}
    .header {{ text-align:center; padding:40px 0; border-bottom:2px solid #e2e8f0; }}
    .header h1 {{ font-size:28px; margin-bottom:8px; }}
    .header p {{ color:#64748b; font-size:14px; }}
    .score-card {{ display:inline-block; margin-top:16px; padding:16px 32px; border-radius:12px; color:#fff; }}
    .section {{ margin-top:32px; }}
    .section h2 {{ font-size:20px; margin-bottom:16px; padding-bottom:8px; border-bottom:1px solid #e2e8f0; }}
    table {{ width:100%; border-collapse:collapse; font-size:13px; }}
    th, td {{ padding:10px 12px; text-align:left; border-bottom:1px solid #e2e8f0; }}
    th {{ background:#f1f5f9; font-weight:600; }}
    tr:hover {{ background:#f8fafc; }}
    .badge {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:600; }}
    .footer {{ text-align:center; padding:20px; color:#94a3b8; font-size:12px; margin-top:40px; border-top:1px solid #e2e8f0; }}
</style></head>
<body>
<div class="container">
    <div class="header">
        <h1>IoT Vulnerability Assessment Report</h1>
        <p>Generated: {report.generated_at} | Network: {report.network_cidr}</p>
        <div class="score-card" style="background:{score_color}">
            <div style="font-size:36px;font-weight:700">{report.overall_risk_score:.1f}</div>
            <div style="font-size:14px;opacity:0.9">Overall Risk Score ({report.overall_severity})</div>
        </div>
    </div>

    <div class="section">
        <h2>Summary</h2>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px">
            <div style="background:#fff;padding:20px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.1);text-align:center">
                <div style="font-size:28px;font-weight:700">{report.total_devices}</div>
                <div style="font-size:13px;color:#64748b">Devices Found</div>
            </div>
            <div style="background:#fff;padding:20px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.1);text-align:center">
                <div style="font-size:28px;font-weight:700">{report.total_vulnerabilities}</div>
                <div style="font-size:13px;color:#64748b">Vulnerabilities</div>
            </div>
            <div style="background:#fff;padding:20px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.1);text-align:center">
                <div style="font-size:28px;font-weight:700">{len(report.recommendations)}</div>
                <div style="font-size:13px;color:#64748b">Recommendations</div>
            </div>
            <div style="background:#fff;padding:20px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.1);text-align:center">
                <div style="font-size:28px;font-weight:700">{(report.overall_risk_score / 10 * 100):.0f}%</div>
                <div style="font-size:13px;color:#64748b">Risk Level</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Risk Distribution</h2>
        {severity_bar}
    </div>

    <div class="section">
        <h2>Discovered Devices ({report.total_devices})</h2>
        <table><thead><tr><th>IP Address</th><th>MAC Address</th><th>Manufacturer</th><th>Type</th><th>Open Ports</th></tr></thead>
        <tbody>{device_rows}</tbody></table>
    </div>

    <div class="section">
        <h2>Vulnerabilities Detected ({report.total_vulnerabilities})</h2>
        <table><thead><tr><th>CVE ID</th><th>Device</th><th>Description</th><th>Severity</th><th>CVSS</th></tr></thead>
        <tbody>{vuln_rows}</tbody></table>
    </div>

    <div class="section">
        <h2>Security Recommendations ({len(report.recommendations)})</h2>
        <table><thead><tr><th>Device</th><th>Category</th><th>Priority</th><th>Description</th><th>Action</th></tr></thead>
        <tbody>{rec_rows}</tbody></table>
    </div>

    <div class="footer">
        IoT Vulnerability Assessment and Risk Analysis Framework &mdash; Generated automatically
    </div>
</div>
</body></html>"""
