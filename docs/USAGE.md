# Guide d'utilisation — Security Scanner Pipeline

## Prérequis

- Compte GitHub avec GitHub Actions activé
- (Optionnel) Docker installé localement pour tester les builds

## Utilisation directe

### 1. Scanner votre propre code

Forkez ou clonez ce repo, puis remplacez les exemples par vos fichiers :

```bash
# Remplacer l'app Docker exemple par la vôtre
rm -rf examples/docker/*
cp -r /votre/app/* examples/docker/

# Remplacer le Terraform exemple par le vôtre
rm -rf examples/terraform/*
cp -r /votre/infra/* examples/terraform/
```

Poussez sur `main` ou ouvrez une PR — le pipeline se déclenche automatiquement.

### 2. Intégrer dans un repo existant

Copiez le reusable workflow dans votre repo :

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    uses: g-holali-david/hdgavi-security-pipeline/.github/workflows/reusable-security-scan.yml@main
    with:
      docker-context: "."           # Chemin vers le Dockerfile
      terraform-dir: "infra/"       # Chemin vers les .tf (vide = pas de scan)
      scan-docker: true
      scan-iac: true
```

### 3. Générer un rapport en local

```bash
# Installer les dépendances
pip install jinja2

# Lancer le générateur avec vos fichiers SARIF
python scripts/report_generator.py \
  --trivy-sarif /chemin/trivy.sarif \
  --gitleaks-sarif /chemin/gitleaks.sarif \
  --checkov-sarif /chemin/checkov.sarif \
  --grype-sarif /chemin/grype.sarif \
  --output rapport.html
```

### 4. Vérifier les policies en local

```bash
python scripts/policy_check.py \
  --trivy-sarif /chemin/trivy.sarif \
  --gitleaks-sarif /chemin/gitleaks.sarif \
  --checkov-sarif /chemin/checkov.sarif \
  --grype-sarif /chemin/grype.sarif

# Exit code 0 = toutes les policies passent
# Exit code 1 = au moins une violation
echo $?
```

## Consulter les résultats

### GitHub Security Tab

Après chaque push, les résultats SARIF sont uploadés vers **Security > Code scanning alerts** dans le repo GitHub. Chaque scanner a sa propre catégorie.

### Rapport HTML

1. Allez dans **Actions** > dernière exécution du workflow
2. Téléchargez l'artifact `security-report`
3. Ouvrez `security-report.html` dans un navigateur

### Commentaire PR

Sur chaque PR, un commentaire automatique affiche :
- Tableau par scanner (Critical / High / Medium / Low)
- Score global sur 100
- Verdict (PASS / WARN / FAIL)

## Personnalisation

### Modifier les seuils de scoring

Dans `scripts/report_generator.py`, modifiez `SEVERITY_WEIGHTS` :

```python
SEVERITY_WEIGHTS = {
    "critical": 25,  # Pénalité par finding critique
    "high": 10,
    "medium": 3,
    "low": 1,
}
```

### Modifier les policies

Dans `scripts/policy_check.py`, fonction `evaluate_policies()` :

```python
# Exemple : tolérer 1 CVE critique
if trivy_counts["critical"] > 1:  # au lieu de > 0
    violations.append(...)

# Exemple : ajouter une policy sur les findings High
if trivy_counts["high"] > 5:
    violations.append({
        "policy": "max-high-cves",
        "scanner": "Trivy",
        "message": f"Too many high CVEs: {trivy_counts['high']}",
        "severity": "high",
    })
```

### Désactiver un scanner

Dans le workflow principal, commentez ou supprimez le job correspondant, puis ajustez la liste `needs` des jobs `generate-report` et `policy-gate`.
