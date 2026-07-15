#!/usr/bin/env python3
"""
IoT Vulnerability Assessment and Risk Analysis Framework — CLI Entry Point.
Full pipeline: Discovery → Identification → Vulnerability Assessment → Risk Analysis → Recommendations → Report

Usage:
  python run.py                              # scan local network, display results
  python run.py --network 10.0.0.0/24        # scan specific subnet
  python run.py --port-range full            # full port scan (slow)
  python run.py --output ./reports           # save reports to directory
  python run.py --json                       # output JSON to stdout
  python run.py --quiet                      # minimal output
"""
import argparse
import json
import sys
import os

# Add parent dir to path for framework imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from framework.orchestrator import run_pipeline
from framework.reporting import export_html, export_json


def main():
    parser = argparse.ArgumentParser(
        description="IoT Vulnerability Assessment and Risk Analysis Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                                  # Quick scan of local network
  python run.py --network 10.0.0.0/24            # Scan specific subnet
  python run.py --port-range full --output ./reports  # Full scan with report export
  python run.py --json                           # Output results as JSON
        """,
    )
    parser.add_argument("--network", default="192.168.1.0/24",
                        help="Network CIDR to scan (default: 192.168.1.0/24)")
    parser.add_argument("--port-range", choices=["quick", "common", "full"], default="common",
                        help="Port scan depth (default: common)")
    parser.add_argument("--output", default="",
                        help="Directory to save report files (HTML + JSON)")
    parser.add_argument("--json", action="store_true",
                        help="Output report as JSON to stdout")
    parser.add_argument("--html", action="store_true",
                        help="Output report as HTML to stdout")
    parser.add_argument("--quiet", action="store_true",
                        help="Minimal output during scan")
    parser.add_argument("--version", action="version", version="IoT Framework 1.0.0")

    args = parser.parse_args()

    # Run the full pipeline
    report = run_pipeline(
        network=args.network,
        port_range=args.port_range,
        output_dir=args.output,
        quiet=args.quiet,
    )

    # Output formats
    if args.json:
        print(report.to_json())
    elif args.html:
        print(report.to_html())

    # If no output format specified and no output dir, show summary
    if not args.json and not args.html and not args.output:
        print()
        print("Quick Summary:")
        print(f"  Network: {report.network_cidr}")
        print(f"  Devices: {report.total_devices}")
        print(f"  Vulnerabilities: {report.total_vulnerabilities}")
        print(f"  Overall Risk: {report.overall_risk_score}/10 ({report.overall_severity})")
        print(f"  Recommendations: {len(report.recommendations)}")
        print()
        print("Risk Distribution:")
        for sev in ["Critical", "High", "Medium", "Low"]:
            count = report.risk_summary.get(sev, 0)
            if count:
                bar = "█" * count
                print(f"  {sev:10s}: {bar} ({count})")
        print()
        print("Top Recommendations:")
        sorted_recs = sorted(report.recommendations, key=lambda r: {"High": 0, "Medium": 1, "Low": 2}.get(r.priority, 3))
        for r in sorted_recs[:5]:
            print(f"  [{r.priority}] {r.description}")
            print(f"         {r.action[:80]}...")
        print()


if __name__ == "__main__":
    main()
