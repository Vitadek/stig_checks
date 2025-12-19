#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify the operating system is configured to block unauthorized peripherals.
GROUP_ID="V-230524"

# --- Pre-flight Checks ---
# This script requires root privileges to run usbguard commands.
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
  echo "          -> A USBGuard policy must be generated based on currently connected, trusted devices."
  echo "          -> WARNING: Running this command without physical access can lock you out of the system"
  echo "          -> if you are using a USB keyboard or mouse."
  echo "          -> 1. From a root shell on the console, run the following command to generate an allow-list:"
  echo "          ->    # usbguard generate-policy > /etc/usbguard/rules.conf"
  echo "          -> 2. Review the generated '/etc/usbguard/rules.conf' file."
  echo "          -> 3. Enable and start the usbguard service:"
  echo "          ->    # systemctl enable --now usbguard.service"

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

  # Check 1: Check for virtualization and USB devices
  virt_status=$(systemd-detect-virt --quiet)
  is_vm_with_no_usb=false
  if [[ $? -eq 0 ]]; then
      check_results+=("->   System Type: Virtual Machine (${virt_status})")
      # Check if lsusb is available before trying to use it
      if ! command -v lsusb &> /dev/null; then
          check_results+=("->   USB Devices: Cannot check, 'lsusb' command not found.")
      else
          # Check for attached USB devices
          if ! lsusb | grep -q -v "devices"; then
              is_vm_with_no_usb=true
          fi
      fi
  else
      check_results+=("->   System Type: Physical")
  fi
  
  if [[ "$is_vm_with_no_usb" == true ]]; then
      echo "          -> INFO: System is a VM with no attached USB devices. This rule is not a finding."
      echo "          -> Check Results:"
      for result in "${check_results[@]}"; do echo "          $result"; done
      echo "          ->   USB Devices: None found"
      echo "STATUS: not_a_finding"
      exit 0
  fi
  
  # Check 2: Is usbguard package installed?
  if ! rpm -q usbguard &> /dev/null; then
      is_compliant=0
      findings_list+=("-> Finding: The 'usbguard' package is not installed.")
      check_results+=("->   usbguard Package: Not Installed")
  else
      check_results+=("->   usbguard Package: Installed")
      
      # Check 3: Does usbguard have rules configured?
      rules_output=$(usbguard list-rules 2>&1)
      if [[ $? -ne 0 || -z "$rules_output" ]]; then
          is_compliant=0
          findings_list+=("-> Finding: USBGuard service returned no rules or an error.")
          check_results+=("->   USBGuard Rules: Not Configured or Service Error")
      else
          check_results+=("->   USBGuard Rules: Configured")
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
    echo "          -> NOTE: If this system is a virtual machine with no intention of using USB"
    echo "          ->       peripherals, this finding may be considered not applicable."
    echo "STATUS: open"
  fi
fi


