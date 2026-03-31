# Security Scanner Pipeline

[![Security Scan](https://github.com/g-holali-david/hdgavi-security-pipeline/actions/workflows/security-scan.yml/badge.svg)](https://github.com/g-holali-david/hdgavi-security-pipeline/actions/workflows/security-scan.yml)

Automated security scanning pipeline that runs **4 scanners in parallel**, generates a **unified HTML report**, and enforces **policy gates** to block merges on critical findings.

## Scanners

| Scanner | Target | What it detects |
|---------|--------|----------------|
| **Trivy** | Docker images | OS & library CVEs |
| **Grype** | SBOM (via Syft) | Dependency vulnerabilities |
| **Gitleaks** | Git history | Hardcoded secrets & API keys |
| **Checkov** | Terraform | IaC misconfigurations |

## Architecture

```
┌──────────────────┐
│  GitHub Actions   │
│    Pipeline       │
└────────┬─────────┘
         │
   ┌─────┼──────────────────────┐
   │     │                      │
   ▼     ▼         ▼            ▼
 Trivy  Gitleaks  Checkov     Grype
(images)(secrets)(Terraform)  (SBOM)
   │     │         │            │
   └─────┴─────────┴────────────┘
         │
   ┌─────▼─────┐    ┌───────────┐
   │  Unified  │    │  Policy   │
   │  Report   │    │   Gate    │
   │  (HTML)   │    │ (pass/fail)│
   └───────────┘    └───────────┘
```

## Policy Gates

The pipeline **blocks merges** when:
- Critical CVEs are found in container images (Trivy)
- Secrets are detected in the codebase (Gitleaks)
- Critical IaC misconfigurations exist (Checkov)
- Critical dependency vulnerabilities are found (Grype)

PRs are automatically labeled `security-passed` or `security-blocked`.

## Unified Report

The pipeline generates an HTML report with:
- **Security score** (0-100)
- Findings by severity (Critical / High / Medium / Low)
- Per-scanner breakdown with details
- Remediation links

## Reusable Workflow

Use this pipeline in your own repos:

```yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]

jobs:
  security:
    uses: g-holali-david/hdgavi-security-pipeline/.github/workflows/reusable-security-scan.yml@main
    with:
      docker-context: "."
      terraform-dir: "infra/"
```

## Local Usage

Generate a report locally from SARIF files:

```bash
python scripts/report_generator.py \
  --trivy-sarif trivy.sarif \
  --gitleaks-sarif gitleaks.sarif \
  --checkov-sarif checkov.sarif \
  --grype-sarif grype.sarif \
  --output report/security-report.html
```

## Project Structure

```
.
├── .github/workflows/
│   ├── security-scan.yml            # Main pipeline
│   └── reusable-security-scan.yml   # Reusable workflow
├── examples/
│   ├── docker/                      # Sample app (scan target)
│   └── terraform/                   # Sample IaC (scan target)
├── scripts/
│   ├── report_generator.py          # Unified HTML report
│   └── policy_check.py              # Policy gate logic
└── report/                          # Generated reports (gitignored)
```

## Tech Stack

- **CI/CD**: GitHub Actions
- **Scanners**: Trivy, Grype, Gitleaks, Checkov
- **SBOM**: Syft (SPDX format)
- **Report**: Python + HTML/CSS
- **Format**: SARIF (GitHub Security tab integration)

## License

MIT
