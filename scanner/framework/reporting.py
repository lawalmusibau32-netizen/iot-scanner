"""
Module 6: Reporting Module
Generates comprehensive assessment reports in HTML and JSON formats.
"""
import json
import os
from datetime import datetime
from collections import Counter
from .models import Device, Vulnerability, RiskAssessment, Recommendation, Report


def generate_report(network_cidr: str, devices: list[Device],
                    vulnerabilities: list[Vulnerability],
                    risk_assessments: list[RiskAssessment],
                    recommendations: list[Recommendation]) -> Report:
    """Generate a comprehensive assessment report."""
    # Risk summary by severity
    severity_counts = Counter(ra.severity for ra in risk_assessments)

    # Overall risk score (weighted average of top risks)
    if risk_assessments:
        top_risks = sorted(risk_assessments, key=lambda r: r.risk_score, reverse=True)[:5]
        overall_score = round(sum(r.risk_score for r in top_risks) / len(top_risks), 1)
    else:
        overall_score = 0.0

    overall_severity = Vulnerability.classify_severity(overall_score)

    report = Report(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        network_cidr=network_cidr,
        total_devices=len(devices),
        total_vulnerabilities=len(vulnerabilities),
        overall_risk_score=overall_score,
        overall_severity=overall_severity,
        devices=[d.to_dict() for d in devices],
        vulnerabilities=[v.to_dict() for v in vulnerabilities],
        risk_assessments=[r.to_dict() for r in risk_assessments],
        recommendations=[r.to_dict() for r in recommendations],
        risk_summary=dict(severity_counts),
    )

    return report


def export_html(report: Report, output_path: str = "") -> str:
    """Export report as an HTML file. Returns file path."""
    html = report.to_html()
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[reporting] HTML report saved to {output_path}")
    return html


def export_json(report: Report, output_path: str = "") -> str:
    """Export report as a JSON file. Returns file path."""
    json_str = report.to_json()
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
        print(f"[reporting] JSON report saved to {output_path}")
    return json_str
