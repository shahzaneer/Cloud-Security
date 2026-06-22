#!/usr/bin/env bash
# =============================================================================
# scout-suite-scan.sh
# Purpose: Wrapper script to run ScoutSuite multi-cloud security audits across
#          AWS, Azure, and GCP. Produces JSON reports for use in posture
#          management, compliance, and IR triage labs.
#
# Curriculum cross-references:
#   - Compliance-Audit-Gov/posture-management-per-cloud.md
#   - Compliance-Audit-Gov/frameworks-overview-cis-nist-iso-pci.md
#   - Compliance-Audit-Gov/control-vs-policy-vs-guardrail.md
#   - Monitoring-Detection-SIEM/the-security-log-mosaic-per-cloud.md
#   - Storage-Data-Security/ (public bucket detection)
#   - IAM/identity-primitives-per-cloud.md
#   - resources/tool-index.md (ScoutSuite row)
#
# Usage:
#   # All clouds at once (defaults below — override with env vars / args)
#   ./scout-suite-scan.sh --all
#
#   # AWS only
#   ./scout-suite-scan.sh --aws
#
#   # Azure only (replace tenant with your own)
#   ./scout-suite-scan.sh --azure --azure-tenant example.onmicrosoft.com
#
#   # GCP only (replace project-id with your own)
#   ./scout-suite-scan.sh --gcp --gcp-project-id example-project
#
#   # Custom output directory
#   ./scout-suite-scan.sh --all --outdir ./my-results
#
#   # Dry run (show what would be executed)
#   ./scout-suite-scan.sh --all --dry-run
#
# ⚠️  SAFETY NOTE: This script REQUIRES active cloud credentials to function.
#    Never run against production accounts without explicit authorization.
#    ScoutSuite makes read-only API calls, but the scope and volume of calls
#    may trigger API rate limits, CloudTrail/audit log noise, and SIEM alerts.
#    Always coordinate with your SOC team before scanning shared environments.
#
# Requirements:
#   - Python 3.9+ with ScoutSuite installed (`pip install scoutsuite`)
#   - Valid cloud credentials for each target:
#       AWS:   ~/.aws/credentials  or  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
#       Azure: az login (Azure CLI)  or  AZURE_SUBSCRIPTION_ID / AZURE_TENANT_ID
#       GCP:   gcloud auth application-default login  or  GOOGLE_APPLICATION_CREDENTIALS
# =============================================================================

set -euo pipefail

# ---- Defaults ---------------------------------------------------------------
OUTDIR="scout-results"
DRY_RUN=false
SCAN_AWS=false
SCAN_AZURE=false
SCAN_GCP=false
AWS_PROFILE="${AWS_PROFILE:-default}"
AZURE_TENANT="example.onmicrosoft.com"     # placeholder — override with --azure-tenant
GCP_PROJECT_ID="example-project"           # placeholder — override with --gcp-project-id

# ---- Colour helpers ---------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---- Usage ------------------------------------------------------------------
usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Multi-cloud ScoutSuite audit wrapper.

Options:
  --all                  Scan all three clouds (AWS, Azure, GCP)
  --aws                  Scan AWS only
  --azure                Scan Azure only
  --gcp                  Scan GCP only
  --azure-tenant TENANT  Azure tenant for scan (default: example.onmicrosoft.com)
  --gcp-project-id ID    GCP project ID for scan (default: example-project)
  --outdir DIR           Output directory for JSON reports (default: scout-results)
  --dry-run              Print commands without executing
  -h, --help             Show this help message

Examples:
  $0 --all
  $0 --aws
  $0 --azure --azure-tenant mytenant.onmicrosoft.com
  $0 --gcp --gcp-project-id my-gcp-project --outdir ./audit-reports
EOF
}

# ---- Parse CLI args ---------------------------------------------------------
if [[ $# -eq 0 ]]; then
  usage
  exit 0
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)     SCAN_AWS=true; SCAN_AZURE=true; SCAN_GCP=true ;;
    --aws)     SCAN_AWS=true ;;
    --azure)   SCAN_AZURE=true ;;
    --gcp)     SCAN_GCP=true ;;
    --azure-tenant)   shift; AZURE_TENANT="$1" ;;
    --gcp-project-id) shift; GCP_PROJECT_ID="$1" ;;
    --outdir)         shift; OUTDIR="$1" ;;
    --dry-run)        DRY_RUN=true ;;
    --help|-h)        usage; exit 0 ;;
    *)
      log_error "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

# ---- Preflight: check for ScoutSuite ----------------------------------------
check_scout() {
  if ! command -v scout &>/dev/null; then
    log_error "ScoutSuite CLI not found."
    log_error "Install it:  pip install scoutsuite"
    log_error "            or activate your curriculum venv (see setup-venv.sh)"
    exit 1
  fi
  log_info "Found ScoutSuite: $(scout --version 2>&1 || echo 'version unknown')"
}

# ---- Safety banner ----------------------------------------------------------
print_safety_banner() {
  echo ""
  echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${YELLOW}║  ⚠️  SCOUTSUITE SAFETY NOTE                                      ║${NC}"
  echo -e "${YELLOW}║                                                                ║${NC}"
  echo -e "${YELLOW}║  ScoutSuite makes extensive read-only API calls across your     ║${NC}"
  echo -e "${YELLOW}║  cloud environment. This WILL generate:                        ║${NC}"
  echo -e "${YELLOW}║    - CloudTrail / Activity Log / Audit Log events               ║${NC}"
  echo -e "${YELLOW}║    - SIEM / GuardDuty / SCC / Sentinel alerts                   ║${NC}"
  echo -e "${YELLOW}║    - API rate-limit headroom consumption                        ║${NC}"
  echo -e "${YELLOW}║                                                                ║${NC}"
  echo -e "${YELLOW}║  Only scan accounts you own or have explicit authorization      ║${NC}"
  echo -e "${YELLOW}║  to test. Never scan production without prior coordination.     ║${NC}"
  echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════╝${NC}"
  echo ""
}

# ---- Scan functions ---------------------------------------------------------

scan_aws() {
  local outfile="$OUTDIR/aws-${AWS_PROFILE}.json"
  log_info "Starting AWS scan (profile: $AWS_PROFILE)..."
  log_info "Output will be written to: $outfile"

  if $DRY_RUN; then
    echo "  [DRY RUN] scout aws --profile $AWS_PROFILE --report-dir $OUTDIR --no-browser"
    return
  fi

  mkdir -p "$OUTDIR"

  # ScoutSuite for AWS
  # Reference: Compliance-Audit-Gov/posture-management-per-cloud.md
  scout aws \
    --profile "$AWS_PROFILE" \
    --report-dir "$OUTDIR" \
    --no-browser

  log_info "AWS scan complete. Report: $OUTDIR/scoutsuite-report/scoutsuite-results/scoutsuite_results_aws.js"
}

scan_azure() {
  local outfile="$OUTDIR/azure-${AZURE_TENANT}.json"
  log_info "Starting Azure scan (tenant: $AZURE_TENANT)..."
  log_info "Output will be written to: $outfile"

  if $DRY_RUN; then
    echo "  [DRY RUN] scout azure --tenant $AZURE_TENANT --report-dir $OUTDIR --no-browser"
    return
  fi

  mkdir -p "$OUTDIR"

  # ScoutSuite for Azure
  # Reference: Monitoring-Detection-SIEM/azure-log-analytics-and-sentinel.md
  scout azure \
    --tenant "$AZURE_TENANT" \
    --report-dir "$OUTDIR" \
    --no-browser

  log_info "Azure scan complete. Report: $OUTDIR/scoutsuite-report/scoutsuite-results/scoutsuite_results_azure.js"
}

scan_gcp() {
  local outfile="$OUTDIR/gcp-${GCP_PROJECT_ID}.json"
  log_info "Starting GCP scan (project: $GCP_PROJECT_ID)..."
  log_info "Output will be written to: $outfile"

  if $DRY_RUN; then
    echo "  [DRY RUN] scout gcp --project-id $GCP_PROJECT_ID --report-dir $OUTDIR --no-browser"
    return
  fi

  mkdir -p "$OUTDIR"

  # ScoutSuite for GCP
  # Reference: Monitoring-Detection-SIEM/gcp-cloud-audit-logs-and-scc.md
  scout gcp \
    --project-id "$GCP_PROJECT_ID" \
    --report-dir "$OUTDIR" \
    --no-browser

  log_info "GCP scan complete. Report: $OUTDIR/scoutsuite-report/scoutsuite-results/scoutsuite_results_gcp.js"
}

# ---- Credential check helpers -----------------------------------------------

check_aws_creds() {
  log_info "Checking AWS credentials for profile '$AWS_PROFILE'..."
  if ! aws sts get-caller-identity --profile "$AWS_PROFILE" &>/dev/null; then
    log_error "AWS credentials not valid or expired for profile '$AWS_PROFILE'."
    log_error "Run: aws sso login --profile $AWS_PROFILE   or   export AWS_ACCESS_KEY_ID=..."
    return 1
  fi
  local identity
  identity=$(aws sts get-caller-identity --profile "$AWS_PROFILE" 2>/dev/null)
  log_info "AWS identity: $(echo "$identity" | jq -r '.Arn')"
}

check_azure_creds() {
  log_info "Checking Azure credentials..."
  if ! az account show &>/dev/null; then
    log_error "Azure CLI not authenticated. Run: az login"
    return 1
  fi
  local identity
  identity=$(az account show --query "{tenant:tenantId, user:user.name}" -o json 2>/dev/null)
  log_info "Azure identity: $(echo "$identity" | jq -r '.user')"
}

check_gcp_creds() {
  log_info "Checking GCP credentials..."
  if ! gcloud auth application-default print-access-token &>/dev/null; then
    log_error "GCP credentials not valid. Run: gcloud auth application-default login"
    return 1
  fi
  local identity
  identity=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
  log_info "GCP identity: $identity"
}

# =============================================================================
# Main execution
# =============================================================================

check_scout

if $DRY_RUN; then
  log_info "DRY RUN — no scans will be executed."
  echo ""
fi

if ! $DRY_RUN; then
  print_safety_banner
fi

# ---- AWS ----
if $SCAN_AWS; then
  if ! $DRY_RUN; then
    check_aws_creds || exit 1
    echo ""
  fi
  scan_aws
  echo ""
fi

# ---- Azure ----
if $SCAN_AZURE; then
  if ! $DRY_RUN; then
    check_azure_creds || exit 1
    echo ""
  fi
  scan_azure
  echo ""
fi

# ---- GCP ----
if $SCAN_GCP; then
  if ! $DRY_RUN; then
    check_gcp_creds || exit 1
    echo ""
  fi
  scan_gcp
  echo ""
fi

# ---- Summary ----------------------------------------------------------------
if ! $DRY_RUN; then
  log_info "=================================================="
  log_info "All scans complete."
  log_info "Reports written to: $OUTDIR/"
  log_info ""
  log_info "HTML reports can be generated by opening the .html"
  log_info "file in:  $OUTDIR/scoutsuite-report/"
  log_info ""
  log_info "Next steps:"
  log_info "  1. Review findings against CIS benchmarks"
  log_info "     Reference: Compliance-Audit-Gov/frameworks-overview-cis-nist-iso-pci.md"
  log_info "  2. Export findings to Cloud Custodian for remediation"
  log_info "     Reference: Compliance-Audit-Gov/cloud-custodian-and-continuous-compliance.md"
  log_info "  3. Correlate with SIEM alerts"
  log_info "     Reference: Monitoring-Detection-SIEM/alert-to-action-soc-tiers.md"
  log_info "=================================================="
fi
