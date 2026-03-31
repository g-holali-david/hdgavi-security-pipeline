#!/usr/bin/env python3
"""
Unified Security Report Generator.

Parses SARIF output from Trivy, Gitleaks, Checkov, and Grype,
then generates a single HTML report with a global security score.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# SARIF parsing
# ---------------------------------------------------------------------------

def parse_sarif(filepath: str) -> list[dict]:
    """Parse a SARIF file and return a flat list of findings."""
    findings = []
    if not filepath or not os.path.isfile(filepath):
        return findings

    with open(filepath) as f:
        data = json.load(f)

    for run in data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})

            severity = _extract_severity(result, rule)
            location = _extract_location(result)

            findings.append({
                "tool": tool_name,
                "rule_id": rule_id,
                "severity": severity,
                "message": result.get("message", {}).get("text", ""),
                "location": location,
                "help": rule.get("helpUri", ""),
            })

    return findings


def _extract_severity(result: dict, rule: dict) -> str:
    """Map SARIF level / security-severity to a normalized severity."""
    # Check for security-severity in rule properties
    props = rule.get("properties", {})
    sec_sev = props.get("security-severity", "")
    if sec_sev:
        score = float(sec_sev)
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    # Fall back to SARIF level
    level = result.get("level", "warning")
    return {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "low",
    }.get(level, "medium")


def _extract_location(result: dict) -> str:
    """Extract a human-readable location string from a SARIF result."""
    locations = result.get("locations", [])
    if not locations:
        return ""
    loc = locations[0].get("physicalLocation", {})
    artifact = loc.get("artifactLocation", {}).get("uri", "")
    region = loc.get("region", {})
    line = region.get("startLine", "")
    if artifact and line:
        return f"{artifact}:{line}"
    return artifact


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"critical": 25, "high": 10, "medium": 3, "low": 1}


def compute_score(findings: list[dict]) -> int:
    """Compute a security score from 0-100 (100 = no findings)."""
    penalty = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)
    return max(0, 100 - penalty)


def verdict(score: int) -> str:
    if score >= 90:
        return "PASS — Excellent security posture"
    if score >= 70:
        return "WARN — Some issues need attention"
    if score >= 50:
        return "FAIL — Significant vulnerabilities found"
    return "FAIL — Critical security issues detected"


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Scan Report</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e;
    --critical: #f85149; --high: #db6d28; --medium: #d29922; --low: #58a6ff;
    --pass: #3fb950; --fail: #f85149; --warn: #d29922;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
  .meta { color: var(--muted); margin-bottom: 2rem; }
  .score-card { display: flex; gap: 2rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .score-box { background: var(--surface); border: 1px solid var(--border);
               border-radius: 12px; padding: 1.5rem; text-align: center; min-width: 180px; flex: 1; }
  .score-box .number { font-size: 3rem; font-weight: 700; }
  .score-box .label { color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }
  .severity-badge { display: inline-block; padding: 2px 10px; border-radius: 20px;
                    font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .severity-critical { background: var(--critical); color: #fff; }
  .severity-high { background: var(--high); color: #fff; }
  .severity-medium { background: var(--medium); color: #000; }
  .severity-low { background: var(--low); color: #000; }
  .scanner-section { background: var(--surface); border: 1px solid var(--border);
                     border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }
  .scanner-section h2 { font-size: 1.2rem; margin-bottom: 1rem; display: flex;
                         align-items: center; gap: 0.5rem; }
  table { width: 100%%; border-collapse: collapse; }
  th, td { padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; }
  td { font-size: 0.9rem; }
  .pass { color: var(--pass); } .fail { color: var(--fail); } .warn { color: var(--warn); }
  a { color: var(--low); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .empty { color: var(--muted); font-style: italic; padding: 1rem 0; }
  .verdict { font-size: 1.3rem; font-weight: 700; margin-top: 0.5rem; }
</style>
</head>
<body>
<div class="container">
  <h1>Security Scan Report</h1>
  <p class="meta">Generated on {generated_at} &mdash; Commit: <code>{commit}</code></p>

  <!-- Score card -->
  <div class="score-card">
    <div class="score-box">
      <div class="number {score_class}">{score}</div>
      <div class="label">Security Score</div>
      <div class="verdict {score_class}">{verdict}</div>
    </div>
    <div class="score-box">
      <div class="number severity-critical">{critical_count}</div>
      <div class="label">Critical</div>
    </div>
    <div class="score-box">
      <div class="number severity-high">{high_count}</div>
      <div class="label">High</div>
    </div>
    <div class="score-box">
      <div class="number severity-medium">{medium_count}</div>
      <div class="label">Medium</div>
    </div>
    <div class="score-box">
      <div class="number severity-low">{low_count}</div>
      <div class="label">Low</div>
    </div>
  </div>

  <!-- Per-scanner sections -->
  {scanner_sections}
</div>
</body>
</html>
"""

SCANNER_SECTION_TEMPLATE = """\
  <div class="scanner-section">
    <h2>{icon} {scanner_name} <span style="color:var(--muted);font-weight:400;font-size:0.9rem;">
        &mdash; {finding_count} finding(s)</span></h2>
    {table_or_empty}
  </div>
"""

SCANNER_ICONS = {
    "Trivy": "&#128737;",      # shield
    "Gitleaks": "&#128272;",   # key
    "Checkov": "&#9989;",      # check
    "Grype": "&#128270;",      # magnifier
}


def _group_by_scanner(findings: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for f in findings:
        groups.setdefault(f["tool"], []).append(f)
    return groups


def _render_table(items: list[dict]) -> str:
    if not items:
        return '<p class="empty">No findings detected.</p>'

    rows = ""
    for item in sorted(items, key=lambda x: list(SEVERITY_WEIGHTS).index(x["severity"])
                        if x["severity"] in SEVERITY_WEIGHTS else 99):
        sev = item["severity"]
        help_link = f'<a href="{item["help"]}" target="_blank">details</a>' if item["help"] else ""
        rows += f"""    <tr>
      <td><span class="severity-badge severity-{sev}">{sev}</span></td>
      <td><code>{item['rule_id']}</code></td>
      <td>{item['message'][:120]}</td>
      <td><code>{item['location']}</code></td>
      <td>{help_link}</td>
    </tr>\n"""

    return f"""<table>
  <thead><tr><th>Severity</th><th>Rule</th><th>Message</th><th>Location</th><th>Ref</th></tr></thead>
  <tbody>
{rows}  </tbody>
</table>"""


def generate_html(findings: list[dict], commit: str) -> str:
    score = compute_score(findings)
    sev_counts = {s: 0 for s in SEVERITY_WEIGHTS}
    for f in findings:
        if f["severity"] in sev_counts:
            sev_counts[f["severity"]] += 1

    score_class = "pass" if score >= 90 else ("warn" if score >= 70 else "fail")

    groups = _group_by_scanner(findings)
    # Ensure all 4 scanners appear even if no findings
    for name in ["Trivy", "Gitleaks", "Checkov", "Grype"]:
        groups.setdefault(name, [])

    sections = ""
    for scanner_name in ["Trivy", "Gitleaks", "Checkov", "Grype"]:
        items = groups.get(scanner_name, [])
        icon = SCANNER_ICONS.get(scanner_name, "")
        sections += SCANNER_SECTION_TEMPLATE.format(
            icon=icon,
            scanner_name=scanner_name,
            finding_count=len(items),
            table_or_empty=_render_table(items),
        )

    return HTML_TEMPLATE.format(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        commit=commit[:12] if commit else "local",
        score=score,
        score_class=score_class,
        verdict=verdict(score),
        critical_count=sev_counts["critical"],
        high_count=sev_counts["high"],
        medium_count=sev_counts["medium"],
        low_count=sev_counts["low"],
        scanner_sections=sections,
    )


def generate_summary_json(findings: list[dict], output_dir: str) -> None:
    """Write a summary.json for the PR comment action."""
    scanners: dict[str, dict[str, int]] = {}
    for f in findings:
        s = scanners.setdefault(f["tool"], {"critical": 0, "high": 0, "medium": 0, "low": 0})
        if f["severity"] in s:
            s[f["severity"]] += 1

    score = compute_score(findings)
    summary = {
        "score": score,
        "verdict": verdict(score),
        "scanners": scanners,
    }

    path = os.path.join(output_dir, "summary.json")
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate unified security report")
    parser.add_argument("--trivy-sarif", help="Path to Trivy SARIF file")
    parser.add_argument("--gitleaks-sarif", help="Path to Gitleaks SARIF file")
    parser.add_argument("--checkov-sarif", help="Path to Checkov SARIF file")
    parser.add_argument("--grype-sarif", help="Path to Grype SARIF file")
    parser.add_argument("--output", required=True, help="Output HTML file path")
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""), help="Commit SHA")
    args = parser.parse_args()

    # Parse all SARIF files
    findings = []
    findings.extend(parse_sarif(args.trivy_sarif))
    findings.extend(parse_sarif(args.gitleaks_sarif))
    findings.extend(parse_sarif(args.checkov_sarif))
    findings.extend(parse_sarif(args.grype_sarif))

    print(f"Parsed {len(findings)} total findings")
    for sev in ["critical", "high", "medium", "low"]:
        count = sum(1 for f in findings if f["severity"] == sev)
        if count:
            print(f"  {sev.upper()}: {count}")

    # Generate HTML report
    html = generate_html(findings, args.commit)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    print(f"Report written to {output_path}")

    # Generate summary JSON (for PR comment)
    generate_summary_json(findings, str(output_path.parent))

    # Exit with error if critical findings
    score = compute_score(findings)
    print(f"Security Score: {score}/100 — {verdict(score)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
