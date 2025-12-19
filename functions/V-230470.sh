#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify RHEL 8 enables Linux audit logging of the USBGuard daemon.
GROUP_ID="V-230470"

# --- Pre-flight Checks ---
# This script requires root privileges to check system configuration.
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
  
  usbguard_conf="/etc/usbguard/usbguard-daemon.conf"
  correct_setting="AuditBackend=LinuxAudit"
  changes_made=false

  if [[ ! -f "$usbguard_conf" ]]; then
      echo "          -> WARNING: USBGuard config file '${usbguard_conf}' not found. Cannot apply fix."
      echo "STATUS: error"
      exit 1
  fi

  # Check if the correct setting is already present and uncommented
  if ! grep -q "^\s*${correct_setting}\s*$" "$usbguard_conf"; then
      echo "          -> Applying fix: Setting 'AuditBackend=LinuxAudit' in ${usbguard_conf}."
      # If the line exists but is commented or has a different value, replace it
      if grep -q "^\s*#*\s*AuditBackend=" "$usbguard_conf"; then
          sed -i 's|^\s*#*\s*AuditBackend=.*|'"${correct_setting}"'|' "$usbguard_conf"
      else
          # Otherwise, add the line to the file
          echo "${correct_setting}" >> "$usbguard_conf"
      fi
      changes_made=true
  fi
  
  if [[ "$changes_made" == true ]]; then
      echo "          -> Remediation logic has been executed."
      echo "  [WARNING] The usbguard service may need to be restarted for this change to take effect."
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

  # Check 1: Applicability - Is it a VM with no USB?
  virt_status=$(systemd-detect-virt --quiet)
  if [[ $? -eq 0 ]]; then
      check_results+=("->   System Type: Virtual Machine (${virt_status})")
      if command -v lsusb &> /dev/null; then
        if ! lsusb | grep -q -v "devices"; then
            echo "          -> INFO: System is a VM with no attached USB devices. This rule is not a finding."
            echo "          -> Check Results:"
            for result in "${check_results[@]}"; do echo "          $result"; done
            echo "          ->   USB Devices: None found"
            echo "STATUS: not_a_finding"
            exit 0
        fi
      else
        check_results+=("->   USB Device Check: 'lsusb' command not found, cannot determine if USB devices are attached.")
      fi
  else
      check_results+=("->   System Type: Physical")
  fi

  # Check 2: Applicability - Is usbguard installed and enabled?
  if ! rpm -q usbguard &> /dev/null; then
      echo "          -> INFO: 'usbguard' package is not installed. This rule is not applicable."
      echo "STATUS: not_applicable"
      exit 0
  fi
  if ! systemctl is-enabled usbguard.service &> /dev/null; then
      echo "          -> INFO: 'usbguard.service' is not enabled. This rule is not applicable."
      echo "STATUS: not_applicable"
      exit 0
  fi
  check_results+=("->   USBGuard Service: Installed and enabled")

  # Check 3: AuditBackend setting
  usbguard_conf="/etc/usbguard/usbguard-daemon.conf"
  if [[ ! -f "$usbguard_conf" ]]; then
      is_compliant=0
      findings_list+=("-> Finding: USBGuard config file '${usbguard_conf}' not found.")
      check_results+=("->   AuditBackend Setting: Config file not found")
  else
      audit_setting=$(grep -i "^\s*AuditBackend" "$usbguard_conf")
      if [[ -z "$audit_setting" ]]; then
          is_compliant=0
          findings_list+=("-> Finding: 'AuditBackend' setting is missing from '${usbguard_conf}'.")
          check_results+=("->   AuditBackend Setting: Missing")
      elif ! echo "$audit_setting" | grep -q "^\s*AuditBackend=LinuxAudit"; then
          is_compliant=0
          findings_list+=("-> Finding: 'AuditBackend' is not set to 'LinuxAudit'. Current value: ${audit_setting}")
          check_results+=("->   AuditBackend Setting: Incorrect (${audit_setting})")
      else
          check_results+=("->   AuditBackend Setting: Correctly set to 'LinuxAudit'")
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

