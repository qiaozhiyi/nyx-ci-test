#!/usr/bin/env bash
# run_hvci_matrix.sh — ONE-COMMAND HVCI kernel-lab run, end to end:
#
#   cross-build nyx-kernel.exe (x86_64-pc-windows-gnu, on this Mac)
#   → deploy Azure Trusted Launch VM      (deploy_azure_lab.sh)
#   → blob staging + short-lived SAS      (private container in the same RG)
#   → enable VBS+HVCI in the guest        (bootstrap_kernel_lab.ps1 via run-command)
#   → reboot + wait for the VM agent      (spot-eviction aware)
#   → verify HVCI is RUNNING — hard gate  (verify_kernel_env.ps1 -Json)
#   → run the nyx-kernel kit matrix       (run_kernel_matrix.ps1: assess /
#     blind-etw / hide / dump-lsass / pg-window / wdt + Shield BYOVD arm)
#   → pull evidence back                  (results.json + transcript + dmp)
#   → teardown the resource group         (unless KEEP=1)
#
# No RDP, no manual steps: everything guest-side runs through
# 'az vm run-command invoke' (RunPowerShellScript).
#
# COST CEILING (defense in depth — Azure has no hard spend cap per run):
#   1. SPOT=1 by default  → B2s ≈ $0.01-0.02/h instead of ~$0.042/h (eastus,
#      2026-08 pricing; check 'az vm list-skus' / portal for current spot %).
#      Worst case (PAYG, full 90-min budget): < $0.10 compute + ~$0.01 storage.
#   2. MAX_MINUTES=90 wall-clock budget → force teardown when exceeded.
#   3. deploy_azure_lab.sh arms auto-shutdown (default 19:00 UTC) as backstop.
#   4. EXIT trap tears the RG down on any failure (KEEP=1 disables).
#
# Prereqs: az CLI + `az login` + subscription selected; python3; jq;
# rustup target x86_64-pc-windows-gnu (script checks and tells you how to add).
#
# Usage:
#   ./scripts/kernel-lab/run_hvci_matrix.sh
#   KEEP=1 ...         keep the VM+RG after the run (debugging; auto-shutdown still armed)
#   SPOT=0 ...         pay-as-you-go VM (no eviction risk, ~2-4x cost)
#   DRIVER_MODE=wdt    wdt | byovd | both (default both)
#   MAX_MINUTES=120    raise the wall-clock budget
set -euo pipefail

# --- locate the repo root (this script lives in scripts/kernel-lab/) ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RG="${RG:-nyx-kernel-lab}"
LOC="${LOC:-eastus}"
VM="${VM:-nyx-kvm}"
SIZE="${SIZE:-Standard_B2s}"
SPOT="${SPOT:-1}"
KEEP="${KEEP:-0}"
DRIVER_MODE="${DRIVER_MODE:-both}"
MAX_MINUTES="${MAX_MINUTES:-90}"
CONTAINER="evidence"
CLI_MANIFEST="$ROOT/crates/operator-kernel-cli/Cargo.toml"
EXE_SRC="$ROOT/crates/operator-kernel-cli/target/x86_64-pc-windows-gnu/release/nyx-kernel.exe"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="$ROOT/tmp/kernel-lab-evidence/$TS"
DEPLOYED=0   # set once the RG exists — gates the EXIT-trap teardown

log()  { echo "[$(date -u +%H:%M:%S)] $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

# --- cost ceiling #2: wall-clock budget ---------------------------------------
check_budget() {
  if [ $((SECONDS / 60)) -ge "$MAX_MINUTES" ]; then
    fail "MAX_MINUTES=${MAX_MINUTES}m budget exhausted — force teardown (cost ceiling). Rerun with MAX_MINUTES=<n> if this was legitimate work."
  fi
}

# --- cost ceiling #4: teardown on ANY exit ------------------------------------
cleanup() {
  rc=$?
  if [ "$DEPLOYED" = "1" ] && [ "$KEEP" != "1" ]; then
    log "teardown: deleting resource group $RG (KEEP=$KEEP)"
    az group delete -n "$RG" --yes --no-wait 2>/dev/null || true
  elif [ "$DEPLOYED" = "1" ]; then
    log "KEEP=1 — VM left running. Auto-shutdown is armed; full cleanup: $SCRIPT_DIR/deploy_azure_lab.sh teardown"
  fi
  exit $rc
}
trap cleanup EXIT

# ==============================================================================
log "== phase 0: prereqs =="
command -v az      >/dev/null || fail "az CLI missing: brew install azure-cli"
command -v jq      >/dev/null || fail "jq missing: brew install jq"
command -v python3 >/dev/null || fail "python3 missing"
command -v cargo   >/dev/null || fail "cargo missing"
az account show -o none 2>/dev/null || fail "not logged in — run: az login && az account set -s <subscription-id>"
if ! rustup target list --installed 2>/dev/null | grep -q '^x86_64-pc-windows-gnu$'; then
  fail "Windows cross target missing — run: rustup target add x86_64-pc-windows-gnu (plus: brew install mingw-w64)"
fi
SUB="$(az account show --query name -o tsv)"
log "subscription: $SUB"
log "cost estimate: $SIZE spot=$SPOT, budget ${MAX_MINUTES}m → worst case < \$0.10 compute (PAYG B2s ≈ \$0.042/h; spot ≈60-90% off)"

log "== phase 1: cross-build nyx-kernel.exe =="
cargo build --release --target x86_64-pc-windows-gnu --manifest-path "$CLI_MANIFEST"
[ -f "$EXE_SRC" ] || fail "expected binary missing: $EXE_SRC"
log "built: $EXE_SRC ($(stat -f%z "$EXE_SRC" 2>/dev/null || stat -c%s "$EXE_SRC") bytes)"

check_budget
log "== phase 2: deploy Trusted Launch VM (RG=$RG LOC=$LOC VM=$VM SIZE=$SIZE SPOT=$SPOT) =="
RG="$RG" LOC="$LOC" VM="$VM" SIZE="$SIZE" SPOT="$SPOT" "$SCRIPT_DIR/deploy_azure_lab.sh" create
DEPLOYED=1

check_budget
log "== phase 3: blob staging (private container + 3h SAS) =="
ACCT="nyxlab$(python3 -c 'import secrets; print(secrets.token_hex(5))')"   # 16 chars, globally unique
az storage account create -g "$RG" -n "$ACCT" -l "$LOC" \
  --sku Standard_LRS --allow-blob-public-access false --min-tls-version TLS1_2 -o none
KEY="$(az storage account keys list -g "$RG" -n "$ACCT" --query '[0].value' -o tsv)"
az storage container create --account-name "$ACCT" --account-key "$KEY" -n "$CONTAINER" -o none
az storage blob upload --account-name "$ACCT" --account-key "$KEY" \
  -c "$CONTAINER" -n nyx-kernel.exe -f "$EXE_SRC" --overwrite -o none
EXPIRY="$(date -u -v+3H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+3 hours' +%Y-%m-%dT%H:%M:%SZ)"
SAS="$(az storage container generate-sas --account-name "$ACCT" --account-key "$KEY" \
  -n "$CONTAINER" --permissions rwl --expiry "$EXPIRY" --https-only -o tsv)"
SAS_URL="https://$ACCT.blob.core.windows.net/$CONTAINER?$SAS"
log "container: $CONTAINER @ $ACCT (SAS expires $EXPIRY)"

# --- run-command helper: returns the guest's interleaved stdout/stderr ---------
# run-command invoke succeeds when the script RAN; the guest exit code is not
# propagated — gates must parse output (hence POSTURE_JSON / results.json).
run_ps() {  # <script-file> [name=value ...]
  local file="$1"; shift
  az vm run-command invoke -g "$RG" -n "$VM" --command-id RunPowerShellScript \
    --scripts "@$file" "$@" --query 'value[0].message' -o tsv
}

# --- wait for the VM agent after boot/reboot; spot-eviction aware --------------
wait_agent() {
  local deadline=$((SECONDS + 900))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if az vm run-command invoke -g "$RG" -n "$VM" --command-id RunPowerShellScript \
        --scripts 'Write-Host pong' --query 'value[0].message' -o tsv 2>/dev/null | grep -q pong; then
      return 0
    fi
    # Spot eviction deallocates the VM (disk kept) — start it again, once per eviction.
    local power
    power="$(az vm get-instance-view -g "$RG" -n "$VM" \
      --query "statuses[?starts_with(code,'PowerState/')].code|[0]" -o tsv 2>/dev/null || true)"
    if [ "$power" = "PowerState/deallocated" ] && [ "$SPOT" = "1" ]; then
      log "VM deallocated — spot eviction (or auto-shutdown). Attempting az vm start..."
      az vm start -g "$RG" -n "$VM" -o none || true
    fi
    sleep 20
    check_budget
  done
  return 1
}

check_budget
log "== phase 4: enable VBS+HVCI in guest, then reboot =="
# NOTE: capture-then-grep, not 'tee | grep -q' — grep -q closes the pipe early,
# tee dies with SIGPIPE (141) and 'set -o pipefail' would misreport success as
# failure.
BOOT_OUT="$(run_ps "$SCRIPT_DIR/bootstrap_kernel_lab.ps1")"
echo "$BOOT_OUT"
printf '%s\n' "$BOOT_OUT" | grep -q 'Done' \
  || fail "bootstrap_kernel_lab.ps1 did not complete — see output above"
log "guest configured; restarting VM"
az vm restart -g "$RG" -n "$VM" -o none
wait_agent || fail "VM agent never came back after reboot (spot eviction loop? check '$SCRIPT_DIR/deploy_azure_lab.sh status')"

check_budget
log "== phase 5: verify HVCI posture (hard gate) =="
# -Json is a [switch] in the guest script — run-command named-parameter syntax.
VERIFY_OUT="$(run_ps "$SCRIPT_DIR/verify_kernel_env.ps1" --parameters "Json=True")"
echo "$VERIFY_OUT"
POSTURE="$(printf '%s\n' "$VERIFY_OUT" | grep -o 'POSTURE_JSON:{.*}' | tail -1 | sed 's/^POSTURE_JSON://')"
[ -n "$POSTURE" ] || fail "no POSTURE_JSON from verify_kernel_env.ps1 — guest script regression?"
HVCI="$(printf '%s' "$POSTURE" | jq -r '.hvci_running')"
BUILD="$(printf '%s' "$POSTURE" | jq -r '.os_build')"
log "posture: hvci_running=$HVCI build=$BUILD"
if [ "$HVCI" != "true" ]; then
  fail "HVCI is NOT running on the lab VM — the matrix would be meaningless. Posture: $POSTURE"
fi

check_budget
log "== phase 6: nyx-kernel matrix in guest (DRIVER_MODE=$DRIVER_MODE) =="
mkdir -p "$EVIDENCE_DIR"
run_ps "$SCRIPT_DIR/run_kernel_matrix.ps1" \
  --parameters "ContainerSasUrl=$SAS_URL" "DriverMode=$DRIVER_MODE" \
  | tee "$EVIDENCE_DIR/run_command_output.txt"

check_budget
log "== phase 7: pull evidence =="
az storage blob download-batch --account-name "$ACCT" --account-key "$KEY" \
  -s "$CONTAINER" -d "$EVIDENCE_DIR" --overwrite -o none || true
ls -la "$EVIDENCE_DIR"
if [ -f "$EVIDENCE_DIR/results.json" ]; then
  N_FAIL="$(jq -r '.n_fail' "$EVIDENCE_DIR/results.json")"
  log "matrix results: n_fail=$N_FAIL ($(jq -r '[.steps[] | .step + ":" + .verdict] | join(", ")' "$EVIDENCE_DIR/results.json"))"
  if [ "$N_FAIL" != "0" ]; then
    log "NOTE: matrix had $N_FAIL unexpected failure(s) — see $EVIDENCE_DIR/results.json (exit code stays 0; evidence, not a gate)"
  fi
else
  log "WARNING: no results.json downloaded — guest matrix likely failed before upload; see run_command_output.txt"
fi

log "== done. Evidence: $EVIDENCE_DIR =="
log "teardown $( [ "$KEEP" = "1" ] && echo 'SKIPPED (KEEP=1)' || echo 'runs now (RG delete, --no-wait)' )"
