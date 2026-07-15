"""
Orchestrator — runs the full assessment pipeline through all 6 modules.
Pipeline: Discovery → Identification → Vulnerability Assessment → Risk Analysis → Recommendations → Reporting
"""
import time
from typing import Optional
from .discovery import discover
from .identification import identify
from .vulnerability import assess
from .risk import calculate
from .recommendations import generate
from .reporting import generate_report, export_html, export_json
from .models import Device, Vulnerability, RiskAssessment, Recommendation, Report


def run_pipeline(network: str = "192.168.1.0/24",
                 port_range: str = "common",
                 output_dir: str = "",
                 quiet: bool = False) -> Report:
    """Execute the full vulnerability assessment pipeline."""
    if not quiet:
        print("=" * 60)
        print("  IoT Vulnerability Assessment Framework")
        print("=" * 60)
        print(f"  Network: {network}")
        print(f"  Port range: {port_range}")
        print()

    all_devices: list[Device] = []
    all_vulnerabilities: list[Vulnerability] = []
    all_risks: list[RiskAssessment] = []
    all_recommendations: list[Recommendation] = []

    start = time.time()

    # ── Module 1: Network Discovery ─────────────────────────
    if not quiet:
        print("[1/6] Network Discovery...")
    t1 = time.time()
    raw_devices = discover(network)
    if not quiet:
        print(f"       Found {len(raw_devices)} devices ({time.time()-t1:.1f}s)")
        for d in raw_devices:
            print(f"         {d.ip:16s} {d.mac:17s} {d.hostname or '(no hostname)'}")

    # ── Modules 2–5: Per-device pipeline ────────────────────
    for i, device in enumerate(raw_devices):
        if not quiet:
            print(f"\n[{i+1}/{len(raw_devices)}] Analyzing {device.ip}...")

        # Module 2: Device Identification
        if not quiet:
            print(f"  [2/6] Identifying device...")
        t2 = time.time()
        device = identify(device, port_range=port_range)
        all_devices.append(device)
        if not quiet:
            print(f"         Manufacturer: {device.manufacturer}")
            print(f"         Type: {device.device_type}")
            print(f"         Ports: {len(device.open_ports)} open")
            if device.firmware_version:
                print(f"         Firmware: {device.firmware_version}")
        if not quiet:
            print(f"         ({time.time()-t2:.1f}s)")

        # Module 3: Vulnerability Assessment
        if not quiet:
            print(f"  [3/6] Assessing vulnerabilities...")
        t3 = time.time()
        vulns = assess(device)
        all_vulnerabilities.extend(vulns)
        if not quiet:
            print(f"         Found {len(vulns)} vulnerabilities")
            for v in vulns:
                print(f"           [{v.severity:8s}] {v.description[:70]}")
        if not quiet:
            print(f"         ({time.time()-t3:.1f}s)")

        # Module 4: Risk Analysis
        if not quiet:
            print(f"  [4/6] Analyzing risk...")
        t4 = time.time()
        risks = calculate(vulns, device)
        all_risks.extend(risks)
        if not quiet:
            critical = sum(1 for r in risks if r.severity == "Critical")
            high = sum(1 for r in risks if r.severity == "High")
            med = sum(1 for r in risks if r.severity == "Medium")
            low = sum(1 for r in risks if r.severity == "Low")
            print(f"         Critical: {critical}, High: {high}, Medium: {med}, Low: {low}")
        if not quiet:
            print(f"         ({time.time()-t4:.1f}s)")

        # Module 5: Recommendations
        if not quiet:
            print(f"  [5/6] Generating recommendations...")
        t5 = time.time()
        recs = generate(device, vulns, risks)
        all_recommendations.extend(recs)
        if not quiet:
            high_pri = sum(1 for r in recs if r.priority == "High")
            print(f"         {len(recs)} recommendations ({high_pri} high priority)")
        if not quiet:
            print(f"         ({time.time()-t5:.1f}s)")

    # ── Module 6: Reporting ─────────────────────────────────
    if not quiet:
        print(f"\n[6/6] Generating report...")
    t6 = time.time()
    report = generate_report(network, all_devices, all_vulnerabilities,
                             all_risks, all_recommendations)
    if not quiet:
        print(f"       Overall risk score: {report.overall_risk_score} ({report.overall_severity})")
        print(f"       ({time.time()-t6:.1f}s)")

    # Export if output directory specified
    if output_dir:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(output_dir, f"iot_report_{timestamp}.html")
        json_path = os.path.join(output_dir, f"iot_report_{timestamp}.json")
        export_html(report, html_path)
        export_json(report, json_path)

    elapsed = time.time() - start
    if not quiet:
        print(f"\n  Total time: {elapsed:.1f}s")
        print(f"  Devices analyzed: {len(all_devices)}")
        print(f"  Total vulnerabilities: {len(all_vulnerabilities)}")
        print(f"  Total recommendations: {len(all_recommendations)}")
        print("=" * 60)

    return report
