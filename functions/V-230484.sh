#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify the system clock is securely compared with an authoritative time source.
GROUP_ID="V-230484"

# --- Pre-flight Checks ---
# This script requires root privileges to read chrony configuration.
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
  echo "          -> MANUAL REMEDIATION REQUIRED:"
  echo "          -> The NTP server configuration is site-specific and must be set manually."
  echo "          -> 1. Edit the '/etc/chrony.conf' file."
  echo "          -> 2. Ensure at least one 'server' or 'pool' line points to an authoritative"
  echo "          ->    DoD time source."
  echo "          -> 3. Ensure all 'server' or 'pool' lines include 'maxpoll 16' (or a lower number)."
  echo "          ->    Example: server [ntp.server.name] iburst maxpoll 16"
  echo "          -> 4. Restart the chronyd service: sudo systemctl restart chronyd"

  # After providing manual instructions, the status must be 'open' as manual action is needed.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  findings_list=()
  check_results=()
  is_compliant=1 # Assume compliant until a finding is discovered

  chrony_conf="/etc/chrony.conf"

  if [[ ! -f "$chrony_conf" ]]; then
      is_compliant=0
      findings_list+=("-> Finding: chrony configuration file '${chrony_conf}' not found.")
      check_results+=("->   chrony.conf: Not Found")
  else
      # Get all non-commented-out server and pool lines
      server_lines=$(grep -E "^\s*(server|pool)" "$chrony_conf")

      if [[ -z "$server_lines" ]]; then
          is_compliant=0
          findings_list+=("-> Finding: No 'server' or 'pool' lines are configured in '${chrony_conf}'.")
          check_results+=("->   Configured NTP Servers: None")
      else
          check_results+=("->   Configured NTP Servers:")
          # Always add manual check finding
          findings_list+=("-> Finding: Manual review required. Verify the server(s) listed below are authoritative DoD time sources.")
          is_compliant=0 # Set to non-compliant because manual check is needed

          while IFS= read -r line; do
              check_results+=("->     - ${line}")
              # Check for maxpoll value
              if echo "$line" | grep -q "maxpoll"; then
                  maxpoll_val=$(echo "$line" | grep -o 'maxpoll [0-9]\+' | awk '{print $2}')
                  if [[ "$maxpoll_val" -gt 16 ]]; then
                      is_compliant=0
                      findings_list+=("-> Finding: A server is configured with 'maxpoll ${maxpoll_val}', which is greater than 16.")
                  fi
              fi
          done <<< "$server_lines"
      fi
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    # This state is unlikely for this check due to the manual verification step.
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

