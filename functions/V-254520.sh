#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify the operating system prevents nonprivileged users from executing
# privileged functions.
GROUP_ID="V-254520"

# --- Pre-flight Checks ---
# This script requires root privileges to run semanage.
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
  echo "          -> This rule requires manual remediation to determine the correct role for each user."
  echo "          -> Automatic remediation is not available."
  echo "          -> Please use the following commands to map users to the appropriate SELinux role:"
  echo
  echo "          -> To map a user to the 'sysadm_u' role:"
  echo "          ->    sudo semanage login -m -s sysadm_u <username>"
  echo
  echo "          -> To map a user to the 'staff_u' role:"
  echo "          ->    sudo semanage login -m -s staff_u <username>"
  echo
  echo "          -> To map a user to the 'user_u' role (for non-administrators):"
  echo "          ->    sudo semanage login -m -s user_u <username>"
  echo
  echo "          -> Remediation instructions have been displayed."

  # After applying a fix, the status should be 'open' because it requires a re-scan to confirm compliance.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."
  
  findings_list=()
  mappings_list=()
  is_compliant=1 # Assume compliant

  # Check if semanage command exists
  if ! command -v semanage &> /dev/null; then
    is_compliant=0
    findings_list+=("-> Finding: 'semanage' command not found. Cannot check SELinux user mappings.")
  else
    # Get semanage output, skip header and blank lines
    semanage_output=$(semanage login -l 2>/dev/null | sed -e '1,2d' -e '/^$/d')

    if [[ -z "$semanage_output" ]]; then
        is_compliant=0
        findings_list+=("-> Finding: Could not retrieve SELinux login mappings.")
    else
        while IFS= read -r line; do
            login_name=$(echo "$line" | awk '{print $1}')
            selinux_user=$(echo "$line" | awk '{print $2}')
            
            mappings_list+=("Login: ${login_name} -> SELinux User: ${selinux_user}")

            # Skip system accounts that are handled by default policy
            if [[ "$login_name" == "__default__" || "$login_name" == "root" || "$login_name" == "system_u" ]]; then
                continue
            fi

            # Check if the role is one of the approved ones. Any other role is a finding.
            case "$selinux_user" in
                sysadm_u|staff_u|user_u)
                    # This is a technically compliant mapping, but correct assignment still needs manual verification.
                    ;;
                *)
                    # This is a non-compliant mapping
                    is_compliant=0
                    findings_list+=("-> Finding: User '${login_name}' is mapped to a non-compliant SELinux role: '${selinux_user}'.")
                    ;;
            esac
        done <<< "$semanage_output"
    fi
  fi

  # Report the discovered user mappings
  if [[ ${#mappings_list[@]} -gt 0 ]]; then
      echo "          -> Discovered User Mappings:"
      for mapping in "${mappings_list[@]}"; do
          echo "          ->   $mapping"
      done
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "          -> OK: All users are mapped to technically compliant SELinux roles."
    echo "          -> [MANUAL REVIEW REQUIRED] Verify that administrative users are mapped to 'sysadm_u' or 'staff_u' and non-administrative users are mapped to 'user_u'."
    echo "STATUS: not_a_finding"
  else
    echo "          -> FINDING: System is NOT compliant with rule $GROUP_ID."
    for finding in "${findings_list[@]}"; do
        echo "          $finding"
    done
    echo "          -> [MANUAL REVIEW REQUIRED] Verify that administrative users are mapped to 'sysadm_u' or 'staff_u' and non-administrative users are mapped to 'user_u'."
    echo "STATUS: open"
  fi
fi


