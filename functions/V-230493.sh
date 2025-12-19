#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify the operating system is configured to disable the camera when not in use.
GROUP_ID="V-230493"

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
  
  blacklist_conf="/etc/modprobe.d/blacklist.conf"
  install_line="install uvcvideo /bin/false"
  blacklist_line="blacklist uvcvideo"
  changes_made=false

  # Add 'install uvcvideo /bin/false' if not present
  if ! grep -q -r -- "^\s*${install_line}" /etc/modprobe.d/ &>/dev/null; then
      echo "          -> Applying fix: Adding '${install_line}' to ${blacklist_conf}."
      echo "${install_line}" >> "${blacklist_conf}"
      changes_made=true
  fi
  
  # Add 'blacklist uvcvideo' if not present
  if ! grep -q -r -- "^\s*${blacklist_line}" /etc/modprobe.d/ &>/dev/null; then
      echo "          -> Applying fix: Adding '${blacklist_line}' to ${blacklist_conf}."
      echo "${blacklist_line}" >> "${blacklist_conf}"
      changes_made=true
  fi
  
  if [[ "$changes_made" == true ]]; then
      echo "          -> Remediation logic has been executed."
      echo "  [WARNING] A reboot is required for these changes to take effect."
  else
      echo "          -> No remediation needed. Configuration appears correct."
  fi
  
  # After applying a fix, the status must be 'open' as a reboot and re-scan are needed.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  findings_list=()
  check_results=()
  is_compliant=0 # Assume not compliant until a valid configuration is found

  # Check 1: Applicability - does the system have a camera?
  # We check for /dev/video* devices to determine this.
  if ! ls /dev/video* &> /dev/null; then
      echo "          -> INFO: No camera devices (/dev/video*) found. This rule is not applicable."
      echo "          -> Check Results:"
      echo "          ->   Camera Hardware: Not detected"
      echo "STATUS: not_applicable"
      exit 0
  fi
  check_results+=("->   Camera Hardware: Detected (/dev/video* exists)")
  check_results+=("->   Manual Check: Verify any built-in camera has a physical cover or external camera can be disconnected.")

  # Check 2: Software disable via 'install /bin/false'
  install_setting=$(grep -rh "^\s*install uvcvideo /bin/false" /etc/modprobe.d/)
  if [[ -n "$install_setting" ]]; then
      is_compliant=1
      check_results+=("->   Software Disable (install): '${install_setting}'")
  else
      check_results+=("->   Software Disable (install): Not configured")
  fi
  
  # Check 3: Software disable via 'blacklist'
  blacklist_setting=$(grep -rh "^\s*blacklist uvcvideo" /etc/modprobe.d/)
  if [[ -n "$blacklist_setting" ]]; then
      is_compliant=1
      check_results+=("->   Software Disable (blacklist): '${blacklist_setting}'")
  else
      check_results+=("->   Software Disable (blacklist): Not configured")
  fi

  if [[ $is_compliant -eq 0 ]]; then
      findings_list+=("-> Finding: The uvcvideo kernel module is not disabled via modprobe configuration.")
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

