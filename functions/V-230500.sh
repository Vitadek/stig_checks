#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify the firewall is configured to prohibit unnecessary functions, ports, protocols, and/or services.
GROUP_ID="V-230500"

# --- Pre-flight Checks ---
# This script requires root privileges to run firewall-cmd.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Helper Functions ---
function check_firewalld() {
    if ! command -v firewall-cmd &> /dev/null; then
        echo "          -> INFO: 'firewall-cmd' command not found. Assuming firewalld is not in use."
        echo "          ->       This check requires manual verification of the system's firewall configuration."
        echo "STATUS: open"
        exit 0
    fi
}

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."
  echo "          -> MANUAL REMEDIATION REQUIRED:"
  echo "          -> Firewall rules are site-specific and must be configured manually."
  echo "          -> Please update the host's firewall settings to comply with your organization's"
  echo "          -> Ports, Protocols, and Services Management (PPSM) documentation."

  # After providing manual instructions, the status must be 'open' as manual action is needed.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  # Pre-flight check for firewalld
  check_firewalld

  findings_list=()
  check_results=()
  
  # This check always requires manual review, so it's an open finding by default.
  # The script's purpose is to gather the data for that manual review.
  is_compliant=0 # Not compliant by default (requires manual check)

  findings_list+=("-> Finding: Manual review required. Verify the following firewall configuration against your site's Ports, Protocols, and Services Management (PPSM) documentation.")

  check_results+=("->   Firewall Configuration:")
  
  # Get a list of active zones, filtering out interface lines
  active_zones=$(firewall-cmd --get-active-zones 2>/dev/null | grep -v '^[[:space:]]')
  if [[ -z "$active_zones" ]]; then
      check_results+=("->     No active firewall zones found.")
  else
      # Loop through each active zone and list its configuration
      for zone in $active_zones; do
          check_results+=("->     --- Zone: ${zone} (active) ---")
          # firewall-cmd --zone="$zone" --list-all returns multiple lines, read them into the array
          while IFS= read -r line; do
              check_results+=("->       $line")
          done < <(firewall-cmd --zone="$zone" --list-all | sed 's/^[[:space:]]*//')
      done
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    # This state is unlikely to be reached for this specific check.
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


