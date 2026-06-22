#!/usr/bin/env bash
# =============================================================================
# setup-venv.sh
# Purpose: Create a Python virtual environment and install the most common
#          tools used across the cloud-security curriculum. Designed for
#          macOS and Linux learners. Idempotent — safe to re-run.
#
# Curriculum cross-references:
#   - IaC-Security/                       (checkov, cfn-lint)
#   - Storage-Data-Security/              (boto3 for S3 labs)
#   - Secrets-KMS/                        (google-cloud-kms, boto3 KMS)
#   - Blue-Team-Defense/                  (bandit for SAST)
#   - Monitoring-Detection-SIEM/          (cloud SDK clients)
#   - resources/tool-index.md             (full tool catalogue)
#
# Usage:
#   chmod +x setup-venv.sh
#   ./setup-venv.sh                       # full install
#   ./setup-venv.sh --dry-run             # preview without installing
#   ./setup-venv.sh --venv-dir ./sandbox  # custom venv path
#
# Requirements:
#   - python3 (>= 3.9)
#   - pip3 (bundled with python3 or separate)
#   - Homebrew (brew) — macOS; Linux users: install gitleaks manually
# =============================================================================

set -euo pipefail

# ---- Defaults ---------------------------------------------------------------
VENV_DIR=".venv"
DRY_RUN=false

# ---- Parse CLI args ---------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --dry-run)      DRY_RUN=true ;;
    --venv-dir)     shift; VENV_DIR="$1" ;;
    --help|-h)
      echo "Usage: $0 [--dry-run] [--venv-dir <path>]"
      echo ""
      echo "Creates a Python venv and installs common cloud-security tools."
      echo ""
      echo "Options:"
      echo "  --dry-run       Preview actions without making changes"
      echo "  --venv-dir      Path for the virtualenv directory (default: .venv)"
      exit 0
      ;;
  esac
  shift 2>/dev/null || true
done

# ---- Colour helpers ---------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---- Preflight checks -------------------------------------------------------
log_info "Running preflight checks..."

# Check for python3
if ! command -v python3 &>/dev/null; then
  log_error "python3 not found. Install Python >= 3.9 and try again."
  log_error "  macOS:  brew install python@3.11"
  log_error "  Ubuntu: sudo apt install python3 python3-venv python3-pip"
  exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
log_info "Found python3 $PYTHON_VERSION"

# Check for brew (needed for gitleaks on macOS)
if ! command -v brew &>/dev/null; then
  if [[ "$OSTYPE" == "darwin"* ]]; then
    log_warn "Homebrew not found on macOS. gitleaks will be skipped."
    log_warn "Install brew: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
  else
    log_info "Homebrew not found (non-macOS). Install gitleaks via your package manager."
  fi
  HAS_BREW=false
else
  HAS_BREW=true
  log_info "Found brew $(brew --version | head -1)"
fi

# ---- Dry-run path -----------------------------------------------------------
if $DRY_RUN; then
  log_info "DRY RUN — no changes will be made."
  echo ""
  echo "Would create venv at:      $VENV_DIR"
  echo "Would install pip packages:"
  echo "  - boto3  (AWS SDK — used in Storage, IAM, Compute labs)"
  echo "  - azure-mgmt-resource     (Azure SDK — used in IAM, Monitoring labs)"
  echo "  - google-cloud-storage    (GCP SDK — used in Storage labs)"
  echo "  - google-cloud-kms        (GCP KMS — used in Secrets-KMS labs)"
  echo "  - checkov                 (IaC scanning — used in IaC-Security module)"
  echo "  - cfn-lint                (CloudFormation lint — used in IaC-Security)"
  echo "  - bandit                  (Python SAST — used in Cloud-Native-App-Security)"
  if $HAS_BREW; then
    echo "Would install via brew:"
    echo "  - gitleaks               (secret scanner — used across all modules)"
  fi
  echo ""
  echo "Use --venv-dir <path> to choose a different virtualenv location."
  exit 0
fi

# ---- Create virtual environment ---------------------------------------------
log_info "Creating Python virtual environment at '$VENV_DIR'..."
python3 -m venv "$VENV_DIR"

# Activate
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"
log_info "Virtual environment activated ($VENV_DIR)."

# ---- Upgrade pip and install packages ---------------------------------------
log_info "Upgrading pip..."
pip install --quiet --upgrade pip

log_info "Installing pip packages..."

# --- AWS SDK (boto3) ---
# Used across: Storage-Data-Security, IAM, Compute-Container-Security (Lambda),
# Monitoring-Detection-SIEM (CloudTrail, CloudWatch Logs)
pip install --quiet boto3

# --- Azure SDK ---
# Used in: IAM (Azure RBAC), Monitoring (Sentinel), Storage (Blob security)
pip install --quiet azure-mgmt-resource

# --- GCP SDK ---
# Used in: Storage-Data-Security (GCS), Secrets-KMS (Cloud KMS)
pip install --quiet google-cloud-storage google-cloud-kms

# --- IaC security scanners ---
# checkov: scans Terraform, CloudFormation, Kubernetes manifests for misconfigs
#   Reference: IaC-Security/ module, Compliance-Audit-Gov/cloud-custodian-and-continuous-compliance.md
pip install --quiet checkov

# cfn-lint: CloudFormation linting against AWS specification
#   Reference: IaC-Security/
pip install --quiet cfn-lint

# --- SAST for Python (applied in Cloud-Native-App-Security labs) ---
pip install --quiet bandit

# --- General security utilities ---
# semgrep: multi-language SAST (optional, uncomment if needed)
# pip install --quiet semgrep

# detect-secrets: secret scanning pre-commit (optional, uncomment if needed)
# pip install --quiet detect-secrets

# --- Policy-as-code / detection toolchain (optional, uncomment as needed) ---
# pip install --quiet cloud-custodian
# sigmac — install via: pip install sigmatools

log_info "pip packages installed."

# ---- Install gitleaks via Homebrew ------------------------------------------
if $HAS_BREW; then
  if command -v gitleaks &>/dev/null; then
    log_info "gitleaks already installed ($(gitleaks version 2>&1 || true))."
  else
    log_info "Installing gitleaks via Homebrew..."
    brew install gitleaks
    log_info "gitleaks $(gitleaks version 2>&1 || true) installed."
  fi
  log_info "Reference: gitleaks is used for secret scanning in pre-commit hooks"
  log_info "           and CI pipelines. See Storage-Data-Security/ and Secrets-KMS/"
  log_info "           modules for lab integration."
fi

# ---- Verification -----------------------------------------------------------
log_info "--------------------------------------------------"
log_info "Verifying installed tools..."
echo ""

echo "python3  : $(python3 --version)"
echo "pip3     : $(pip --version | head -1)"
echo "boto3    : $(python3 -c 'import boto3; print(boto3.__version__)' 2>/dev/null || echo 'NOT FOUND')"
echo "azure    : $(python3 -c 'import azure.mgmt.resource; print("ok")' 2>/dev/null || echo 'NOT FOUND')"
echo "GCS      : $(python3 -c 'import google.cloud.storage; print("ok")' 2>/dev/null || echo 'NOT FOUND')"
echo "GCP KMS  : $(python3 -c 'import google.cloud.kms; print("ok")' 2>/dev/null || echo 'NOT FOUND')"
echo "checkov  : $(checkov --version 2>/dev/null || echo 'NOT FOUND')"
echo "cfn-lint : $(cfn-lint --version 2>/dev/null || echo 'NOT FOUND')"
echo "bandit   : $(bandit --version 2>/dev/null || echo 'NOT FOUND')"
echo "gitleaks : $(gitleaks version 2>/dev/null || echo 'NOT FOUND (install via brew)')"

log_info "--------------------------------------------------"
log_info "Virtual environment is ready."
log_info ""
log_info "Activate it in your shell:"
log_info "  source $VENV_DIR/bin/activate"
log_info ""
log_info "Deactivate when done:"
log_info "  deactivate"

deactivate 2>/dev/null || true
