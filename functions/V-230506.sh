#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify there are no wireless interfaces configured on the system.
GROUP_ID="V-230506"

# --- Pre-flight Checks ---
# This script requires root privileges to run nmcli commands.
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

  echo "          -> Applying fix: Disabling all wireless radios with 'nmcli radio all off'."
  nmcli radio all off
  echo "          -> Remediation logic has been executed."
  echo "  [WARNING] Review system changes to ensure correctness."

  # After applying a fix, the status should be 'open' because it requires a re-scan to confirm compliance.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  findings_list=()
  check_results=()
  is_compliant=1 # Assume compliant

  # Check 1: Check for any wireless hardware.
  if ! nmcli -t -f TYPE device | grep -q "wifi"; then
      echo "          -> INFO: No wireless hardware radios found. This rule is not applicable."
      echo "          -> Check Results:"
      echo "          ->   Wireless Hardware: Not detected"
      echo "STATUS: not_applicable"
      exit 0
  fi
  check_results+=("->   Wireless Hardware: Detected")

  # Check 2: Check the state of all wireless interfaces.
  has_wireless_interface=false
  # Process substitution is used here to ensure variables are set in the current shell, not a subshell.
  while read -r device type state conn; do
      if [[ "$type" == "wifi" || "$type" == "wifi-p2p" ]]; then
          has_wireless_interface=true
          check_results+=("->   Interface Found: ${device} (${type}), State: ${state}")
          if [[ "$state" == "connected" || "$state" == "connecting" ]]; then
              is_compliant=0
              findings_list+=("-> Finding: Wireless interface '${device}' is in a '${state}' state.")
          fi
      fi
  done < <(nmcli device status | tail -n +2)

  if [[ "$has_wireless_interface" == false ]]; then
      check_results+=("->   Wireless Interfaces: None configured or detected by NetworkManager.")
  fi

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

