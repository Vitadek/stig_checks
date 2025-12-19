#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify RHEL 8 enables auditing of processes that start prior to the audit daemon.
GROUP_ID="V-230468"

# --- Pre-flight Checks ---
# This script requires root privileges to check and modify grub configuration.
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
  changes_made=false

  # Apply fix to current kernel configuration
  if ! grub2-editenv list | grep -q 'audit=1'; then
      echo "          -> Applying fix: Running 'grubby' to update kernel arguments."
      grubby --update-kernel=ALL --args="audit=1"
      changes_made=true
  fi

  # Apply fix to default grub config to persist across kernel updates
  default_grub_file="/etc/default/grub"
  if grep -q "^GRUB_CMDLINE_LINUX=" "$default_grub_file"; then
      # Line exists, check if audit=1 is present
      if ! grep "^GRUB_CMDLINE_LINUX=" "$default_grub_file" | grep -q "audit=1"; then
          echo "          -> Applying fix: Adding 'audit=1' to GRUB_CMDLINE_LINUX in ${default_grub_file}."
          # Add audit=1 to the existing arguments
          sed -i 's/\(GRUB_CMDLINE_LINUX=".*\)"/\1 audit=1"/' "$default_grub_file"
          changes_made=true
      fi
  else
      # Line does not exist, add it
      echo "          -> Applying fix: Adding 'GRUB_CMDLINE_LINUX=\"audit=1\"' to ${default_grub_file}."
      echo "GRUB_CMDLINE_LINUX=\"audit=1\"" >> "$default_grub_file"
      changes_made=true
  fi
  
  if [[ "$changes_made" == true ]]; then
      echo "          -> Remediation logic has been executed."
      echo "  [WARNING] A reboot may be required for changes to take full effect."
  else
      echo "          -> No remediation needed. Configuration appears correct."
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

  # Check 1: Verify current kernel parameters
  kernel_opts=$(grub2-editenv list | grep "kernelopts")
  check_results+=("->   Running Kernel Args: ${kernel_opts}")
  if ! echo "$kernel_opts" | grep -q "audit=1"; then
    is_compliant=0
    findings_list+=("-> Finding: Early process auditing ('audit=1') is not enabled in the running configuration.")
  fi

  # Check 2: Verify persistent grub configuration
  default_grub_file="/etc/default/grub"
  if [[ -f "$default_grub_file" ]]; then
      persistent_opts=$(grep "^GRUB_CMDLINE_LINUX=" "$default_grub_file")
      check_results+=("->   Persistent Grub Config (${default_grub_file}): ${persistent_opts}")
      if ! echo "$persistent_opts" | grep -q "audit=1"; then
          is_compliant=0
          findings_list+=("-> Finding: Early process auditing ('audit=1') is not set in '${default_grub_file}' to persist on kernel updates.")
      fi
  else
      is_compliant=0
      findings_list+=("-> Finding: Grub default configuration file '${default_grub_file}' not found.")
      check_results+=("->   Persistent Grub Config (${default_grub_file}): File not found.")
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

