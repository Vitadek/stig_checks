#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify that kernel core dumps are disabled unless needed.
GROUP_ID="V-230310"

# --- Pre-flight Checks ---
# This script requires root privileges to manage systemd services.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."

  if systemctl is-active --quiet kdump.service; then
      echo "          -> Applying fix: Disabling kdump.service..."
      systemctl disable --now kdump.service &>/dev/null
      echo "          -> Remediation logic has been executed."
      echo "  [WARNING] The kdump service has been disabled. If kernel core dumps are an"
      echo "          -> operational requirement, this must be documented with the ISSO"
      echo "          -> and the service should be re-enabled."
  else
      echo "          -> No remediation needed. The kdump.service is not active."
  fi

  # After applying a fix, the status must be 'open' as a re-scan is needed.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  findings_list=()
  check_results=()
  is_compliant=1 # Assume compliant

  # Check if the kdump service is active
  if systemctl is-active --quiet kdump.service; then
      is_compliant=0
      service_status="Active"
      findings_list+=("-> Finding: The 'kdump.service' is active. Verify with the System Administrator and ISSO if this is an operational requirement.")
  else
      service_status="Inactive"
  fi
  check_results+=("->   kdump.service status: ${service_status}")

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "          -> OK: System is compliant with rule $GROUP_ID."
    echo "          -> Check Results:"
    for result in "${check_results[@]}"; do echo "          $result"; done
    echo "STATUS: not_a_finding"
  else
    echo "          -> FINDING: System is NOT compliant with rule $GROUP_ID."
    echo "          -> Check Results:"
    for result in "${check_results[@]}"; do echo "          $result"; done
    for finding in "${findings_list[@]}"; do
        echo "          $finding"
    done
    echo "STATUS: open"
  fi
fi

