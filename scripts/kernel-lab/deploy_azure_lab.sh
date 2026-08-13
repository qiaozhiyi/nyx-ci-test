#!/usr/bin/env bash
# deploy_azure_lab.sh — provision an x64 Windows kernel-research VM on Azure
# with Trusted Launch (VBS), ready for HVCI / PatchGuard / driver verification.
#
# Why Azure: the kernelsdk work is x64-only (PRCB gs:[0x20], Peekaboo, vuln-
# driver IOCTL wires). Apple-Silicon Parallels can only run ARM64 Windows (an
# ARM64 kernel — wrong architecture). Azure Trusted Launch Gen2 VMs expose
# real Hyper-V VBS to the guest, so HVCI (memory integrity) and Credential
# Guard can be switched on inside the VM — no nested-virt gymnastics.
#
# Prereqs: az CLI installed (brew install azure-cli), `az login` done,
# subscription selected (`az account set -s <sub>`).
#
# Usage:
#   ./scripts/kernel-lab/deploy_azure_lab.sh                 # create everything
#   ./scripts/kernel-lab/deploy_azure_lab.sh teardown        # delete the RG
#   ./scripts/kernel-lab/deploy_azure_lab.sh ip              # print VM public IP
#
# Env overrides: RG, LOC, VM, SIZE, ADMIN_USER, SPOT=1
set -euo pipefail

RG="${RG:-nyx-kernel-lab}"
LOC="${LOC:-eastus}"
VM="${VM:-nyx-kvm}"
SIZE="${SIZE:-Standard_B2s}"       # ~$0.0416/h; bump to Standard_D2s_v3 for heavier work
ADMIN_USER="${ADMIN_USER:-nyxlab}"
SPOT="${SPOT:-0}"

cmd="${1:-create}"

case "$cmd" in
  teardown)
    az group delete -n "$RG" --yes --no-wait
    echo "teardown started (resource group $RG)"
    exit 0 ;;
  ip)
    az vm show -d -g "$RG" -n "$VM" --query publicIps -o tsv
    exit 0 ;;
  create) ;;
  *) echo "unknown command: $cmd" >&2; exit 1 ;;
esac

# Generate a one-off admin password; printed once, never stored.
ADMIN_PASS="$(python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(20)) + "#1A")')"

echo "==> resource group $RG ($LOC)"
az group create -n "$RG" -l "$LOC" -o none

echo "==> VM $VM ($SIZE, win11-24h2-pro x64, Trusted Launch: secure-boot+vTPM)"
SPOT_ARGS=()
if [ "$SPOT" = "1" ]; then
  SPOT_ARGS=(--priority Spot --eviction-policy Deallocate --max-price -1)
  echo "    (spot pricing enabled)"
fi
az vm create \
  --resource-group "$RG" \
  --name "$VM" \
  --image MicrosoftWindowsDesktop:windows-11:win11-24h2-pro:latest \
  --size "$SIZE" \
  --security-type TrustedLaunch \
  --enable-secure-boot true \
  --enable-vtpm true \
  --admin-username "$ADMIN_USER" \
  --admin-password "$ADMIN_PASS" \
  --public-ip-sku Standard \
  --nsg-rule RDP \
  "${SPOT_ARGS[@]}" \
  -o none

# NOTE: default Trusted Launch = plain Secure Boot (NOT "Secure Boot with
# DMA") — memory integrity is unsupported with SB+DMA on Azure VMs; the
# default is exactly what we need.

echo "==> auto-shutdown 19:00 (cost guard; deallocate manually when idle)"
az vm auto-shutdown -g "$RG" -n "$VM" --time 1900 -o none || true

IP="$(az vm show -d -g "$RG" -n "$VM" --query publicIps -o tsv)"
cat <<EOF

DONE.
  Public IP : $IP
  RDP       : mstsc /v:$IP  (user $ADMIN_USER)
  Password  : $ADMIN_PASS   <-- shown once; store it in your password manager

Next:
  1. RDP in, copy scripts/kernel-lab/bootstrap_kernel_lab.ps1 + verify_kernel_env.ps1 into the VM.
  2. Elevated PowerShell:  Set-ExecutionPolicy Bypass -Scope Process; .\\bootstrap_kernel_lab.ps1
  3. Reboot, then:  .\\verify_kernel_env.ps1   — expect VBS running + HVCI running.
  4. Driver experiments:
     - BYOVD (e.g. RTCore64): first turn OFF "Microsoft vulnerable driver
       blocklist" (Windows Security → Device security → Core isolation) —
       it is ON by default when memory integrity is on (KB5020779).
     - test-signed own driver: requires Secure Boot OFF:
         az vm deallocate -g $RG -n $VM
         az vm update -g $RG -n $VM --security-type TrustedLaunch --enable-secure-boot false --enable-vtpm true
         az vm start -g $RG -n $VM
       then in VM: bcdedit /set testsigning on && shutdown /r /t 0
  5. Idle cost: deallocate when done —  az vm deallocate -g $RG -n $VM
     Full cleanup:  $0 teardown
EOF
