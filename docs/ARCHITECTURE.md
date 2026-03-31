# Architecture — Security Scanner Pipeline

## Vue d'ensemble

Ce pipeline exécute **4 scanners de sécurité en parallèle** via GitHub Actions, puis agrège les résultats dans un rapport HTML unifié et applique des policy gates pour bloquer les merges en cas de vulnérabilité critique.

## Diagramme de flux

```
┌─────────────────────────────────────────────────────┐
│              GitHub Actions — Trigger               │
│         (push main / pull_request main)             │
└────────────────────┬────────────────────────────────┘
                     │
        ┌────────────┼────────────┬────────────┐
        │            │            │            │
        ▼            ▼            ▼            ▼
  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
  │  Trivy   │ │ Gitleaks │ │ Checkov  │ │  Grype   │
  │  (Job 1) │ │  (Job 2) │ │  (Job 3) │ │  (Job 4) │
  │          │ │          │ │          │ │          │
  │ Image    │ │ Secret   │ │ IaC      │ │ SBOM +   │
  │ CVE scan │ │ detection│ │ security │ │ dep scan │
  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘
       │  SARIF      │  SARIF     │  SARIF      │  SARIF
       │             │            │             │
       └──────┬──────┴─────┬──────┴──────┬──────┘
              │            │             │
              ▼            ▼             ▼
     ┌────────────┐  ┌───────────┐  ┌─────────────┐
     │  GitHub    │  │  Unified  │  │   Policy    │
     │  Security  │  │  HTML     │  │    Gate     │
     │  Tab       │  │  Report   │  │  (Job 6)   │
     │ (auto)     │  │  (Job 5)  │  │             │
     └────────────┘  └─────┬─────┘  └──────┬──────┘
                           │               │
                           ▼               ▼
                    ┌────────────┐  ┌────────────┐
                    │  Artifact  │  │  PR Label  │
                    │  Download  │  │  + Comment │
                    └────────────┘  └────────────┘
```

## Composants

### 1. Scanners (jobs parallèles)

| Scanner | Version | Cible | Format sortie | Action GitHub |
|---------|---------|-------|---------------|---------------|
| **Trivy** | 0.28.0 | Image Docker | SARIF + JSON | `aquasecurity/trivy-action` |
| **Gitleaks** | latest | Historique Git | SARIF + JSON | `gitleaks/gitleaks-action` |
| **Checkov** | v12 | Fichiers Terraform | SARIF + JSON | `bridgecrewio/checkov-action` |
| **Grype** | v5 | SBOM (via Syft) | SARIF + JSON | `anchore/scan-action` |

Chaque scanner :
- Produit un fichier SARIF (standard de l'industrie)
- Upload le SARIF vers l'onglet **GitHub Security** (Code Scanning Alerts)
- Sauvegarde les résultats comme **artifacts** pour le rapport unifié

### 2. Rapport unifié (`scripts/report_generator.py`)

**Entrée** : 4 fichiers SARIF (un par scanner)
**Sortie** : `report/security-report.html` + `report/summary.json`

Fonctionnalités :
- Parse les fichiers SARIF et normalise les sévérités
- Calcule un **score de sécurité** (0-100) basé sur les pénalités :
  - Critical : -25 points
  - High : -10 points
  - Medium : -3 points
  - Low : -1 point
- Génère un rapport HTML responsive avec thème dark
- Produit un `summary.json` pour le commentaire PR automatique

**Verdict** :
- 90-100 : PASS — Excellent security posture
- 70-89 : WARN — Some issues need attention
- 50-69 : FAIL — Significant vulnerabilities found
- 0-49 : FAIL — Critical security issues detected

### 3. Policy Gate (`scripts/policy_check.py`)

**Entrée** : 4 fichiers SARIF
**Sortie** : `policy-result.json` + exit code (0=pass, 1=fail)

Politiques appliquées :

| Politique | Scanner | Condition de blocage |
|-----------|---------|---------------------|
| `no-critical-cves` | Trivy | CVE critique dans l'image |
| `no-secrets` | Gitleaks | Secret détecté dans le code |
| `no-critical-iac` | Checkov | Misconfiguration IaC critique |
| `no-critical-deps` | Grype | Vulnérabilité dépendance critique |

Actions sur PR :
- Label `security-passed` ou `security-blocked`
- Commentaire automatique avec tableau récapitulatif

### 4. Reusable Workflow

Fichier : `.github/workflows/reusable-security-scan.yml`

Permet d'intégrer ce pipeline dans d'autres repos via `workflow_call` :

```yaml
jobs:
  security:
    uses: g-holali-david/hdgavi-security-pipeline/.github/workflows/reusable-security-scan.yml@main
    with:
      docker-context: "."
      terraform-dir: "infra/"
      scan-docker: true
      scan-iac: true
```

**Inputs** :
- `docker-context` : chemin du contexte Docker (défaut: `.`)
- `terraform-dir` : chemin des fichiers Terraform (défaut: vide = pas de scan IaC)
- `scan-docker` : activer le scan image (défaut: `true`)
- `scan-iac` : activer le scan IaC (défaut: `true`)

**Outputs** :
- `security-score` : score 0-100
- `policy-passed` : `true` / `false`

## Permissions GitHub Actions

```yaml
permissions:
  contents: read          # Checkout du code
  security-events: write  # Upload SARIF vers Security tab
  pull-requests: write    # Commentaire + labels sur PR
  actions: read           # Lecture des artifacts
```

## Exemples inclus (cibles de scan)

- `examples/docker/` : Application Flask Python avec Dockerfile
- `examples/terraform/` : Module VPC + S3 AWS avec quelques issues intentionnelles
