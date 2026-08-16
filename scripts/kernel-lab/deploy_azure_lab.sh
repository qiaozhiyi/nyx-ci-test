#!/usr/bin/env bash
# deploy_azure_lab.sh — provision an x64 Windows kernel-research VM on Azure
# (Trusted Launch Gen2), for PatchGuard / driver / WFP verification.
#
# Why Azure: the kernelsdk work is x64-only (PRCB gs:[0x20], Peekaboo, vuln-
# driver IOCTL wires). Apple-Silicon Parallels can only run ARM64 Windows (an
# ARM64 kernel — wrong architecture). NOTE: the HVCI-on verification matrix
# was ABANDONED 2026-08-16 — the shipped BYOVD drivers are clean of the MS
# blocklist so HVCI posture gates nothing we ship. Trusted Launch is kept
# because it is the flexible SKU (Secure Boot toggleable for test-signing);
# the guest bootstrap no longer enables VBS/HVCI.
#
# Usage:
#   ./scripts/kernel-lab/deploy_azure_lab.sh                 # create everything (idempotent)
#   ./scripts/kernel-lab/deploy_azure_lab.sh teardown        # delete the RG (idempotent)
#   ./scripts/kernel-lab/deploy_azure_lab.sh ip              # print VM public IP
#   ./scripts/kernel-lab/deploy_azure_lab.sh status          # VM power state (spot-eviction check)
#
# Env overrides: RG, LOC, VM, SIZE, ADMIN_USER, SPOT=1, AUTO_SHUTDOWN_TIME=1900
# (UTC), MY_IP=<ip> (restrict the RDP NSG rule to this source IP).
set -euo pipefail

RG="${RG:-nyx-kernel-lab}"
LOC="${LOC:-eastus}"
VM="${VM:-nyx-kvm}"
SIZE="${SIZE:-Standard_B2s}"       # ~$0.0416/h PAYG eastus (2026-08); spot ≈60-90% off
ADMIN_USER="${ADMIN_USER:-nyxlab}"
SPOT="${SPOT:-0}"
AUTO_SHUTDOWN_TIME="${AUTO_SHUTDOWN_TIME:-1900}"  # UTC hhmm — az vm auto-shutdown --time is UTC
MY_IP="${MY_IP:-}"

cmd="${1:-create}"

# ---- prereq checks (fail with an actionable error, not an az stack trace) ----
need_az() {
  if ! command -v az >/dev/null 2>&1; then
    echo "ERROR: az CLI not found. Install: brew install azure-cli" >&2
    exit 1
  fi
  if ! az account show -o none 2>/dev/null; then
    echo "ERROR: not logged in / no subscription selected." >&2
    echo "  run: az login && az account set -s <subscription-id>" >&2
    echo "  list subscriptions: az account list -o table" >&2
    exit 1
  fi
}

vm_exists() { az vm show -g "$RG" -n "$VM" -o none 2>/dev/null; }

print_next_steps() {
  cat <<EOF

Next:
  1. RDP in, copy scripts/kernel-lab/bootstrap_kernel_lab.ps1 + verify_kernel_env.ps1 into the VM.
  2. Elevated PowerShell:  Set-ExecutionPolicy Bypass -Scope Process; .\bootstrap_kernel_lab.ps1
  3. Reboot, then:  .\verify_kernel_env.ps1   — expect test-signing ON; VBS/HVCI OFF is FINE
     (the HVCI matrix was abandoned 2026-08-16; run_kernel_matrix.ps1 runs on
      a plain x64 VM, manually or via 'az vm run-command').
  4. Driver experiments:
     - BYOVD (WDTKernel / Shield — neither is on the MS vulnerable driver
       blocklist): loads with the blocklist ON, no toggle needed.
       A blocklisted driver would need the blocklist OFF first.
       Headless: .\bootstrap_kernel_lab.ps1 -DisableBlocklist   (needs reboot)
       GUI:      Windows Security → Device security → Core isolation.
     - test-signed own driver: requires Secure Boot OFF:
         az vm deallocate -g $RG -n $VM
         az vm update -g $RG -n $VM --security-type TrustedLaunch --enable-secure-boot false --enable-vtpm true
         az vm start -g $RG -n $VM
       (bootstrap_kernel_lab.ps1 already enables testsigning; reboot applies it)
  5. Idle cost: deallocate when done —  az vm deallocate -g $RG -n $VM
     Full cleanup:  $0 teardown
EOF
}

case "$cmd" in
  teardown)
    need_az
    if az group show -n "$RG" -o none 2>/dev/null; then
      az group delete -n "$RG" --yes --no-wait
      echo "teardown started (resource group $RG)"
    else
      echo "resource group $RG does not exist — nothing to do"
    fi
    exit 0 ;;
  ip)
    need_az
    az vm show -d -g "$RG" -n "$VM" --query publicIps -o tsv
    exit 0 ;;
  status)
    need_az
    az vm get-instance-view -g "$RG" -n "$VM" \
      --query "{power:statuses[?starts_with(code,'PowerState/')].code|[0], prov:statuses[?starts_with(code,'ProvisioningState/')].code|[0]}" \
      -o table
    exit 0 ;;
  create) ;;
  *) echo "unknown command: $cmd (create|teardown|ip|status)" >&2; exit 1 ;;
esac

need_az
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 needed for password generation" >&2; exit 1; }

# ---- idempotency: never regenerate the admin password over an existing VM ----
# The password is shown ONCE at creation. A re-run must not silently rotate it
# (az vm create on an existing VM updates in place and would lock out the
# operator who saved the first password).
if vm_exists; then
  echo "==> VM $VM already exists in $RG — not recreating (idempotent re-run)."
  echo "    password was printed at first creation; to start over: $0 teardown"
  IP="$(az vm show -d -g "$RG" -n "$VM" --query publicIps -o tsv)"
  echo "    Public IP : $IP   (user $ADMIN_USER)"
  # Re-assert the cost guard even on re-run (it is the only recurring safety net).
  az vm auto-shutdown -g "$RG" -n "$VM" --time "$AUTO_SHUTDOWN_TIME" -o none \
    && echo "==> auto-shutdown confirmed at ${AUTO_SHUTDOWN_TIME} UTC" \
    || echo "WARNING: auto-shutdown could not be (re)configured — cost guard NOT armed" >&2
  print_next_steps
  exit 0
fi

# Generate a one-off admin password; printed once, never stored.
ADMIN_PASS="$(python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(20)) + "#1A")')"

echo "==> resource group $RG ($LOC)"
az group create -n "$RG" -l "$LOC" -o none

echo "==> VM $VM ($SIZE, win11-24h2-pro x64, Trusted Launch: secure-boot+vTPM)"
SPOT_ARGS=()
if [ "$SPOT" = "1" ]; then
  SPOT_ARGS=(--priority Spot --eviction-policy Deallocate --max-price -1)
  # --max-price -1 = pay up to the full on-demand price (capacity eviction is
  # the only risk). --eviction-policy Deallocate keeps the disk so the VM can
  # simply be restarted after an eviction.
  echo "    (spot pricing: eviction-policy=Deallocate, max-price=on-demand cap)"
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

# ---- cost guard: auto-shutdown MUST be armed (verified, not best-effort) ----
echo "==> auto-shutdown ${AUTO_SHUTDOWN_TIME} UTC (cost guard; also deallocate manually when idle)"
if ! az vm auto-shutdown -g "$RG" -n "$VM" --time "$AUTO_SHUTDOWN_TIME" -o none; then
  echo "ERROR: auto-shutdown configuration failed — the cost guard is NOT armed." >&2
  echo "       arm it manually: az vm auto-shutdown -g $RG -n $VM --time $AUTO_SHUTDOWN_TIME" >&2
  exit 1
fi

# ---- optional NSG lockdown: --nsg-rule RDP opens 3389 to 0.0.0.0/0 ----
if [ -n "$MY_IP" ]; then
  NSG="$(az network nsg list -g "$RG" --query '[0].name' -o tsv)"
  # The rule name differs by az CLI vintage ("rdp" vs "default-allow-rdp") —
  # resolve it by destination port instead of guessing.
  RULE="$(az network nsg rule list -g "$RG" --nsg-name "$NSG" \
    --query "[?destinationPortRange=='3389'].name | [0]" -o tsv)"
  if [ -n "$RULE" ]; then
    az network nsg rule update -g "$RG" --nsg-name "$NSG" -n "$RULE" \
      --source-address-prefixes "$MY_IP/32" -o none
    echo "==> RDP restricted to $MY_IP/32 (NSG $NSG rule $RULE)"
  else
    echo "WARNING: no 3389 NSG rule found to restrict" >&2
  fi
else
  echo "WARNING: RDP is open to the internet (default NSG rule)." >&2
  echo "         re-run with MY_IP=<your-ip> to restrict, or fix later:" >&2
  echo "         az network nsg rule update -g $RG --nsg-name ${VM}NSG -n default-allow-rdp --source-address-prefixes <ip>/32" >&2
fi

IP="$(az vm show -d -g "$RG" -n "$VM" --query publicIps -o tsv)"
cat <<EOF

DONE.
  Public IP : $IP
  RDP       : mstsc /v:$IP  (user $ADMIN_USER)
  Password  : $ADMIN_PASS   <-- shown once; store it in your password manager
EOF
if [ "$SPOT" = "1" ]; then
  echo "  Spot      : eviction deallocates the VM (disk kept) — recover with: az vm start -g $RG -n $VM"
fi
print_next_steps
