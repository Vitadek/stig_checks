#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify a unique name is set for the grub superusers account.
GROUP_ID="V-244521"

# --- Pre-flight Checks ---
# This script requires root privileges to read grub configuration.
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
  echo "          -> A unique superuser name and a strong password must be set manually."
  echo "          -> 1. Edit the '/etc/grub.d/01_users' file."
  echo "          -> 2. Add or modify the following lines, replacing '[someuniquestringhere]' with a"
  echo "          ->    unique name and generating a strong password hash for '${GRUB2_PASSWORD}':"
  echo "          ->    set superusers=\"[someuniquestringhere]\""
  echo "          ->    export superusers"
  echo "          ->    password_pbkdf2 [someuniquestringhere] \${GRUB2_PASSWORD}"
  echo "          -> 3. Generate a new grub.cfg file with the command:"
  echo "          ->    sudo grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg"

  # After providing manual instructions, the status should be 'open' as manual action is needed.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  findings_list=()
  check_results=()
  is_compliant=1 # Assume compliant

  # Check 1: System Boot Mode (BIOS or UEFI)
  if [[ ! -d "/sys/firmware/efi" ]]; then
    echo "          -> INFO: System is not booted in UEFI mode. This rule is not applicable."
    echo "          -> Check Results:"
    echo "          ->   Boot Mode: BIOS/Legacy"
    echo "STATUS: not_applicable"
    exit 0
  fi
  check_results+=("->   Boot Mode: UEFI")

  # Check 2: GRUB Configuration File
  grub_cfg_path="/boot/efi/EFI/redhat/grub.cfg"
  if [[ ! -f "$grub_cfg_path" ]]; then
      is_compliant=0
      findings_list+=("-> Finding: GRUB config file '${grub_cfg_path}' not found.")
  else
    check_results+=("->   GRUB Config: ${grub_cfg_path}")
    
    # Check 3: Superusers setting
    superuser_line=$(grep -iw "set superusers" "$grub_cfg_path")
    if [[ -z "$superuser_line" ]]; then
        is_compliant=0
        findings_list+=("-> Finding: 'set superusers' line is missing from GRUB config.")
        check_results+=("->   Superuser Name: Not Set")
    else
        superuser_name=$(echo "$superuser_line" | sed -n 's/set superusers="\([^"]*\)".*/\1/p')
        check_results+=("->   Superuser Name: '${superuser_name}'")

        if [[ -z "$superuser_name" ]]; then
            is_compliant=0
            findings_list+=("-> Finding: 'superusers' name is set but is empty.")
        else
            # Check 4: Compare superuser name against OS accounts
            os_users=$(cut -d: -f1 /etc/passwd)
            if echo "$os_users" | grep -q -w "$superuser_name"; then
                is_compliant=0
                findings_list+=("-> Finding: 'superusers' name ('${superuser_name}') matches an OS account name.")
            fi
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

