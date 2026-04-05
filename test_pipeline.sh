#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# test_pipeline.sh — Teste chaque outil de sécurité sur les fichiers
# intentionnellement vulnérables et vérifie qu'ils détectent bien.
#
# Usage : bash test_pipeline.sh
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

check() {
    local tool="$1"
    local expected="$2"   # 0 = doit réussir, 1 = doit échouer (trouver des vulnérabilités)
    local exit_code="$3"

    if [ "$exit_code" -ne 0 ] && [ "$expected" -eq 1 ]; then
        echo -e "${GREEN}[PASS]${NC} $tool — vulnérabilités détectées comme attendu"
        PASS=$((PASS + 1))
    elif [ "$exit_code" -eq 0 ] && [ "$expected" -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} $tool — aucune erreur inattendue"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}[FAIL]${NC} $tool — résultat inattendu (exit=$exit_code, attendu=$expected)"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "══════════════════════════════════════════════════"
echo "  TEST DU PIPELINE — fichiers vulnérables"
echo "══════════════════════════════════════════════════"
echo ""

# ─── 1. Gitleaks ───────────────────────────────────────
echo -e "${YELLOW}[1/7] Gitleaks — détection de secrets${NC}"
pip install gitleaks 2>/dev/null || true
if command -v gitleaks &>/dev/null; then
    gitleaks detect --source . --verbose 2>&1 || exit_code=$?
    check "Gitleaks" 1 "${exit_code:-0}"
else
    echo "      → Gitleaks non installé, skip (utiliser via GitHub Actions)"
fi

# ─── 2. Bandit ─────────────────────────────────────────
echo ""
echo -e "${YELLOW}[2/7] Bandit — SAST Python${NC}"
pip install bandit -q
bandit app/app_vulnerable.py -f text 2>&1; exit_code=$?
check "Bandit" 1 "$exit_code"

# ─── 3. Safety CLI ─────────────────────────────────────
echo ""
echo -e "${YELLOW}[3/7] Safety CLI — CVE dans les dépendances${NC}"
pip install safety -q
safety check -r app/requirements_vulnerable.txt 2>&1; exit_code=$?
check "Safety CLI" 1 "$exit_code"

# ─── 4. Semgrep ────────────────────────────────────────
echo ""
echo -e "${YELLOW}[4/7] Semgrep — SAST multi-langage${NC}"
pip install semgrep -q
semgrep scan \
    --config "p/python" \
    --config "p/owasp-top-ten" \
    --config "p/secrets" \
    app/app_vulnerable.py 2>&1; exit_code=$?
check "Semgrep" 1 "$exit_code"

# ─── 5. Hadolint ───────────────────────────────────────
echo ""
echo -e "${YELLOW}[5/7] Hadolint — Dockerfile lint${NC}"
if command -v hadolint &>/dev/null; then
    hadolint app/Dockerfile.vulnerable 2>&1; exit_code=$?
    check "Hadolint" 1 "$exit_code"
elif command -v docker &>/dev/null; then
    docker run --rm -i hadolint/hadolint < app/Dockerfile.vulnerable 2>&1; exit_code=$?
    check "Hadolint (Docker)" 1 "$exit_code"
else
    echo "      → Hadolint non disponible, skip"
fi

# ─── 6. Checkov — IaC K8s ──────────────────────────────
echo ""
echo -e "${YELLOW}[6/7] Checkov — scan IaC Kubernetes${NC}"
pip install checkov -q
checkov -f k8s/deployment_vulnerable.yaml --framework kubernetes 2>&1; exit_code=$?
check "Checkov" 1 "$exit_code"

# ─── 7. Trivy ──────────────────────────────────────────
echo ""
echo -e "${YELLOW}[7/7] Trivy — scan image container${NC}"
if command -v docker &>/dev/null; then
    echo "  Construction de l'image vulnérable..."
    docker build -f app/Dockerfile.vulnerable -t flask-vulnerable:test ./app 2>&1
    trivy image flask-vulnerable:test --severity HIGH,CRITICAL 2>&1; exit_code=$?
    check "Trivy" 1 "$exit_code"
    docker rmi flask-vulnerable:test 2>/dev/null || true
else
    echo "      → Docker non disponible, skip"
fi

# ─── Résumé ────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════"
echo -e "  Résultats : ${GREEN}${PASS} PASS${NC} / ${RED}${FAIL} FAIL${NC}"
echo "══════════════════════════════════════════════════"
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
