#!/usr/bin/env python3
"""
Policy Gate — Evaluates scan results against security policies.

Exit code 0 = all policies pass, exit code 1 = policy violation.
Writes policy-result.json for downstream consumption.
"""

import argparse
import json
import os
import sys
from pathlib import Path


def parse_sarif_severities(filepath: str) -> dict[str, int]:
    """Count findings by severity from a SARIF file."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    if not filepath or not os.path.isfile(filepath):
        return counts

    with open(filepath) as f:
        data = json.load(f)

    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})

            # Determine severity
            props = rule.get("properties", {})
            sec_sev = props.get("security-severity", "")
            if sec_sev:
                score = float(sec_sev)
                if score >= 9.0:
                    counts["critical"] += 1
                elif score >= 7.0:
                    counts["high"] += 1
                elif score >= 4.0:
                    counts["medium"] += 1
                else:
                    counts["low"] += 1
            else:
                level = result.get("level", "warning")
                sev = {"error": "high", "warning": "medium", "note": "low"}.get(level, "medium")
                counts[sev] += 1

    return counts


def check_gitleaks_secrets(filepath: str) -> int:
    """Return the number of secrets found by Gitleaks."""
    if not filepath or not os.path.isfile(filepath):
        return 0

    with open(filepath) as f:
        data = json.load(f)

    count = 0
    for run in data.get("runs", []):
        count += len(run.get("results", []))

    return count


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

def evaluate_policies(
    trivy_counts: dict[str, int],
    gitleaks_secrets: int,
    checkov_counts: dict[str, int],
    grype_counts: dict[str, int],
) -> list[dict]:
    """Evaluate all policies and return a list of violations."""
    violations = []

    # Policy 1: No critical CVEs (Trivy)
    if trivy_counts["critical"] > 0:
        violations.append({
            "policy": "no-critical-cves",
            "scanner": "Trivy",
            "message": f"{trivy_counts['critical']} critical CVE(s) found in container image",
            "severity": "critical",
        })

    # Policy 2: No secrets in code (Gitleaks)
    if gitleaks_secrets > 0:
        violations.append({
            "policy": "no-secrets",
            "scanner": "Gitleaks",
            "message": f"{gitleaks_secrets} secret(s) detected in the repository",
            "severity": "critical",
        })

    # Policy 3: No high-severity IaC misconfigurations (Checkov)
    if checkov_counts["critical"] > 0:
        violations.append({
            "policy": "no-critical-iac",
            "scanner": "Checkov",
            "message": f"{checkov_counts['critical']} critical IaC misconfiguration(s) found",
            "severity": "critical",
        })

    # Policy 4: No critical dependency vulnerabilities (Grype)
    if grype_counts["critical"] > 0:
        violations.append({
            "policy": "no-critical-deps",
            "scanner": "Grype",
            "message": f"{grype_counts['critical']} critical dependency vulnerability(ies) found",
            "severity": "critical",
        })

    return violations


def main():
    parser = argparse.ArgumentParser(description="Security policy gate")
    parser.add_argument("--trivy-sarif", help="Path to Trivy SARIF file")
    parser.add_argument("--gitleaks-sarif", help="Path to Gitleaks SARIF file")
    parser.add_argument("--checkov-sarif", help="Path to Checkov SARIF file")
    parser.add_argument("--grype-sarif", help="Path to Grype SARIF file")
    args = parser.parse_args()

    # Parse results
    trivy_counts = parse_sarif_severities(args.trivy_sarif)
    gitleaks_secrets = check_gitleaks_secrets(args.gitleaks_sarif)
    checkov_counts = parse_sarif_severities(args.checkov_sarif)
    grype_counts = parse_sarif_severities(args.grype_sarif)

    # Evaluate policies
    violations = evaluate_policies(trivy_counts, gitleaks_secrets, checkov_counts, grype_counts)

    passed = len(violations) == 0
    result = {
        "passed": passed,
        "violations": violations,
        "summary": {
            "trivy": trivy_counts,
            "gitleaks": {"secrets": gitleaks_secrets},
            "checkov": checkov_counts,
            "grype": grype_counts,
        },
    }

    # Write result file
    Path("policy-result.json").write_text(json.dumps(result, indent=2))

    # Print summary
    print("=" * 60)
    print("SECURITY POLICY GATE")
    print("=" * 60)

    if passed:
        print("\n  PASSED — All security policies satisfied.\n")
    else:
        print(f"\n  FAILED — {len(violations)} policy violation(s):\n")
        for v in violations:
            print(f"    [{v['severity'].upper()}] {v['policy']}: {v['message']}")

    print("=" * 60)

    # Summary table
    print(f"\n  Trivy    : C={trivy_counts['critical']} H={trivy_counts['high']} "
          f"M={trivy_counts['medium']} L={trivy_counts['low']}")
    print(f"  Gitleaks : {gitleaks_secrets} secret(s)")
    print(f"  Checkov  : C={checkov_counts['critical']} H={checkov_counts['high']} "
          f"M={checkov_counts['medium']} L={checkov_counts['low']}")
    print(f"  Grype    : C={grype_counts['critical']} H={grype_counts['high']} "
          f"M={grype_counts['medium']} L={grype_counts['low']}")
    print()

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
