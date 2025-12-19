#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify firewalld is configured to employ a deny-all, allow-by-exception policy.
GROUP_ID="V-230504"

# --- Pre-flight Checks ---
# This script requires root privileges to check firewall settings.
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
  echo "          -> The firewall must be configured with a deny-all policy. This requires"
  echo "          -> creating a new zone and adding mission-essential exceptions."
  echo "          -> 1. Create a new permanent zone (e.g., 'custom'):"
  echo "          ->    sudo firewall-cmd --permanent --new-zone=custom"
  echo "          -> 2. Copy the 'drop' zone profile to your new zone's file:"
  echo "          ->    sudo cp /usr/lib/firewalld/zones/drop.xml /etc/firewalld/zones/custom.xml"
  echo "          -> 3. (Optional) Edit the custom.xml to add a description or exceptions."
  echo "          -> 4. Reload the firewall to recognize the new zone:"
  echo "          ->    sudo firewall-cmd --reload"
  echo "          -> 5. Set the new zone as the default:"
  echo "          ->    sudo firewall-cmd --set-default-zone=custom"
  echo "          -> 6. Assign interfaces to the new zone:"
  echo "          ->    sudo firewall-cmd --permanent --zone=custom --change-interface=<interface_name>"
  echo "          -> 7. Reload the firewall one final time:"
  echo "          ->    sudo firewall-cmd --reload"

  # After providing manual instructions, the status must be 'open' as manual action is needed.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  findings_list=()
  check_results=()
  is_compliant=1 # Assume compliant

  # Check 1: Is firewalld installed?
  if ! rpm -q firewalld &> /dev/null; then
      is_compliant=0
      findings_list+=("-> Finding: The 'firewalld' package is not installed. If an alternate firewall is in use, verify its configuration manually.")
      check_results+=("->   firewalld Package: Not Installed")
  else
      check_results+=("->   firewalld Package: Installed")
      
      # Check 2: Is firewalld running?
      state=$(firewall-cmd --state 2>/dev/null)
      check_results+=("->   firewalld State: ${state:-Not running or error}")
      if [[ "$state" != "running" ]]; then
          is_compliant=0
          findings_list+=("-> Finding: The 'firewalld' service is not running.")
      else
          # Check 3: Get active zones
          active_zones=$(firewall-cmd --get-active-zones | awk '/^[a-zA-Z]/ {print $1}')
          check_results+=("->   Active Zones: ${active_zones:-None}")
          if [[ -z "$active_zones" ]]; then
              is_compliant=0
              findings_list+=("-> Finding: There are no active firewall zones.")
          else
              # Check 4: Check the target of each active zone
              for zone in $active_zones; do
                  target=$(firewall-cmd --info-zone="$zone" | grep "target:" | awk '{print $2}')
                  check_results+=("->     - Zone '${zone}' Target: ${target}")
                  if [[ "$target" != "DROP" && "$target" != "%%REJECT%%" ]]; then
                      is_compliant=0
                      findings_list+=("-> Finding: The target for active zone '${zone}' is set to '${target}', not 'DROP'.")
                  fi
              done
          fi
      fi
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


