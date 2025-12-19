#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify RHEL 8 allocates a sufficient audit_backlog_limit.
GROUP_ID="V-230469"

# --- Pre-flight Checks ---
# This script requires root privileges to check and modify grub configuration.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Helper Functions ---
function get_arg_value() {
    local args="$1"
    local key="$2"
    # Extracts the value of a key=value pair from a string of arguments
    echo "$args" | grep -o "${key}=[0-9]\+" | cut -d'=' -f2
}

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."
  changes_made=false
  required_value=8192

  # Apply fix to current kernel configuration
  kernel_opts=$(grub2-editenv list | grep "kernelopts")
  current_backlog=$(get_arg_value "$kernel_opts" "audit_backlog_limit")
  
  if [[ -z "$current_backlog" || "$current_backlog" -lt "$required_value" ]]; then
      echo "          -> Applying fix: Running 'grubby' to set 'audit_backlog_limit=${required_value}'."
      grubby --update-kernel=ALL --args="audit_backlog_limit=${required_value}"
      changes_made=true
  fi

  # Apply fix to default grub config to persist across kernel updates
  default_grub_file="/etc/default/grub"
  if grep -q "^GRUB_CMDLINE_LINUX=" "$default_grub_file"; then
      persistent_opts=$(grep "^GRUB_CMDLINE_LINUX=" "$default_grub_file")
      persistent_backlog=$(get_arg_value "$persistent_opts" "audit_backlog_limit")
      
      if [[ -z "$persistent_backlog" || "$persistent_backlog" -lt "$required_value" ]]; then
          echo "          -> Applying fix: Ensuring 'audit_backlog_limit=${required_value}' is set in ${default_grub_file}."
          # If the key exists, update it. Otherwise, add it.
          if echo "$persistent_opts" | grep -q "audit_backlog_limit="; then
              sed -i "s/audit_backlog_limit=[0-9]\+/audit_backlog_limit=${required_value}/" "$default_grub_file"
          else
              sed -i "s/\(GRUB_CMDLINE_LINUX=\"[^\"]*\)\"/\1 audit_backlog_limit=${required_value}\"/" "$default_grub_file"
          fi
          changes_made=true
      fi
  else
      echo "          -> Applying fix: Adding 'GRUB_CMDLINE_LINUX=\"audit_backlog_limit=${required_value}\"' to ${default_grub_file}."
      echo "GRUB_CMDLINE_LINUX=\"audit_backlog_limit=${required_value}\"" >> "$default_grub_file"
      changes_made=true
  fi
  
  if [[ "$changes_made" == true ]]; then
      echo "          -> Remediation logic has been executed."
      echo "  [WARNING] A reboot may be required for these changes to take full effect."
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
  required_value=8192

  # Check 1: Verify current kernel parameters
  kernel_opts=$(grub2-editenv list | grep "kernelopts")
  check_results+=("->   Running Kernel Args: ${kernel_opts}")
  current_backlog=$(get_arg_value "$kernel_opts" "audit_backlog_limit")
  
  if [[ -z "$current_backlog" ]]; then
      is_compliant=0
      findings_list+=("-> Finding: 'audit_backlog_limit' is not set in the running kernel configuration.")
  elif [[ "$current_backlog" -lt "$required_value" ]]; then
      is_compliant=0
      findings_list+=("-> Finding: 'audit_backlog_limit' is set to '${current_backlog}', which is less than the required '${required_value}'.")
  fi

  # Check 2: Verify persistent grub configuration
  default_grub_file="/etc/default/grub"
  if [[ -f "$default_grub_file" ]]; then
      persistent_opts=$(grep "^GRUB_CMDLINE_LINUX=" "$default_grub_file")
      check_results+=("->   Persistent Grub Config (${default_grub_file}): ${persistent_opts}")
      persistent_backlog=$(get_arg_value "$persistent_opts" "audit_backlog_limit")
      
      if [[ -z "$persistent_backlog" ]]; then
          is_compliant=0
          findings_list+=("-> Finding: 'audit_backlog_limit' is not set in '${default_grub_file}' to persist on kernel updates.")
      elif [[ "$persistent_backlog" -lt "$required_value" ]]; then
          is_compliant=0
          findings_list+=("-> Finding: 'audit_backlog_limit' is set to '${persistent_backlog}' in '${default_grub_file}', which is less than the required '${required_value}'.")
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

