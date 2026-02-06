#!/usr/bin/env python3
"""Generate Evidence summary report from ci_evidence.jsonl.

Creates HTML dashboard summarizing:
- MCPSafetyScanner execution stats
- Auto Gate decisions
- Council evaluations and decisions
- Retest queue activity
"""

import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


def load_evidence(evidence_path="observability/policy/ci_evidence.jsonl"):
    """Load Evidence events from JSONL."""
    events = []
    path = Path(evidence_path)

    if not path.exists():
        print(f"Warning: Evidence file not found: {evidence_path}")
        return events

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Warning: Skipping malformed line: {e}")

    return events


def generate_html_report(events):
    """Generate HTML report from Evidence events."""
    # Metrics
    total_events = len(events)
    mcpsafety_scans = [e for e in events if e.get("scan_type") == "mcpsafety"]
    auto_gate_decisions = [e for e in events if e.get("event") == "auto_gate_decision"]
    retest_enqueued = [e for e in events if e.get("event") == "retest_enqueued"]
    council_runs = [e for e in events if e.get("event") == "mcp_council_run"]
    allowlist_signed = [
        e for e in events if e.get("event") == "allowlist_snapshot_signed"
    ]
    ci_errors = [e for e in events if e.get("event") == "ci_error"]

    # Decision breakdown
    decisions = Counter(e.get("decision") for e in council_runs if "decision" in e)

    # MCPSafetyScanner status breakdown
    mcpsafety_status = Counter(
        e.get("status") for e in mcpsafety_scans if "status" in e
    )

    # Auto Gate breakdown
    gate_decisions = {}
    for e in auto_gate_decisions:
        gate = e.get("gate", "unknown")
        decision = e.get("decision", "unknown")
        gate_decisions[gate] = gate_decisions.get(gate, Counter())
        gate_decisions[gate][decision] += 1

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Gateway Evidence Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .metric {{ display: inline-block; margin: 15px 20px 15px 0; padding: 15px 25px; background: #f9f9f9; border-left: 4px solid #4CAF50; }}
        .metric-value {{ font-size: 32px; font-weight: bold; color: #4CAF50; }}
        .metric-label {{ font-size: 14px; color: #666; margin-top: 5px; }}
        .status-pass {{ color: #4CAF50; }}
        .status-fail {{ color: #f44336; }}
        .status-skip {{ color: #FF9800; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4CAF50; color: white; }}
        .timestamp {{ color: #999; font-size: 12px; }}
        .error {{ background: #ffebee; padding: 15px; border-left: 4px solid #f44336; margin: 15px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>MCP Gateway Evidence Report</h1>
        <p class="timestamp">Generated: {datetime.now().isoformat()}</p>
        <p class="timestamp">Total Events: {total_events}</p>
        
        <h2>Overview</h2>
        <div class="metric">
            <div class="metric-value">{len(mcpsafety_scans)}</div>
            <div class="metric-label">MCPSafetyScanner Scans</div>
        </div>
        <div class="metric">
            <div class="metric-value">{len(auto_gate_decisions)}</div>
            <div class="metric-label">Auto Gate Decisions</div>
        </div>
        <div class="metric">
            <div class="metric-value">{len(retest_enqueued)}</div>
            <div class="metric-label">Retests Enqueued</div>
        </div>
        <div class="metric">
            <div class="metric-value">{len(council_runs)}</div>
            <div class="metric-label">Council Evaluations</div>
        </div>
        <div class="metric">
            <div class="metric-value">{len(allowlist_signed)}</div>
            <div class="metric-label">Allowlist Snapshots Signed</div>
        </div>
        
        <h2>MCPSafetyScanner Status</h2>
        <table>
            <thead>
                <tr><th>Status</th><th>Count</th></tr>
            </thead>
            <tbody>
"""

    for status, count in mcpsafety_status.most_common():
        status_class = f"status-{status}" if status in ["pass", "fail", "skip"] else ""
        html += f"<tr><td class='{status_class}'>{status}</td><td>{count}</td></tr>\n"

    html += """
            </tbody>
        </table>
        
        <h2>Council Decisions</h2>
        <table>
            <thead>
                <tr><th>Decision</th><th>Count</th></tr>
            </thead>
            <tbody>
"""

    for decision, count in [
        ("allow", decisions.get("allow", 0)),
        ("quarantine", decisions.get("quarantine", 0)),
        ("deny", decisions.get("deny", 0)),
    ]:
        html += f"<tr><td>{decision}</td><td>{count}</td></tr>\n"

    html += """
            </tbody>
        </table>
        
        <h2>Auto Gate Decisions</h2>
        <table>
            <thead>
                <tr><th>Gate</th><th>RUN</th><th>SKIP</th></tr>
            </thead>
            <tbody>
"""

    for gate, counts in sorted(gate_decisions.items()):
        html += f"<tr><td>{gate}</td><td>{counts.get('RUN', 0)}</td><td>{counts.get('SKIP', 0)}</td></tr>\n"

    html += """
            </tbody>
        </table>
"""

    # CI Errors section
    if ci_errors:
        html += """
        <h2>CI Errors</h2>
"""
        for error in ci_errors:
            html += f"""
        <div class="error">
            <strong>{error.get('component', 'unknown')}</strong>: {error.get('error', 'No description')}
            <br><small>Action: {error.get('action_required', 'N/A')}</small>
        </div>
"""

    html += """
    </div>
</body>
</html>
"""

    return html


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate Evidence report")
    parser.add_argument(
        "--input",
        default="observability/policy/ci_evidence.jsonl",
        help="Path to Evidence JSONL file",
    )
    parser.add_argument(
        "--output",
        default="observability/dashboard/report.html",
        help="Output HTML file path",
    )

    args = parser.parse_args()

    # Load Evidence
    events = load_evidence(args.input)

    if not events:
        print("No Evidence events found. Generating empty report.")

    # Generate report
    html = generate_html_report(events)

    # Save report
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")

    print(f"✓ Evidence report generated: {output_path}")
    print(f"  Total events: {len(events)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
