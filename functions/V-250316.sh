#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify SELinux context for a non-default pam_faillock tally directory.
GROUP_ID="V-250316"

# --- Pre-flight Checks ---
# This script requires root privileges to run semanage, restorecon, and read system config.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Helper Function ---
get_rhel_version() {
    if [[ -f /etc/redhat-release ]]; then
        grep -oP '(?<=release )[0-9]+\.[0-9]+' /etc/redhat-release
    else
        echo "0.0"
    fi
}

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."

  # Find the non-default tally directory from pam configuration.
  tally_dir=$(grep -whr "pam_faillock.so.*dir=" /etc/pam.d/password-auth /etc/pam.d/system-auth | sed -n 's/.*dir=\([^ ]*\).*/\1/p' | head -n 1)

  if [[ -n "$tally_dir" ]]; then
    echo "          -> Applying fix: Setting SELinux context for '${tally_dir}'."
    semanage fcontext -a -t faillog_t "${tally_dir}(/.*)?"
    restorecon -R -v "$tally_dir"
    echo "          -> Remediation logic has been executed."
  else
    echo "          -> No non-default 'dir=' option found for pam_faillock. No remediation needed."
  fi

  # After applying a fix, the status should be 'open' because it requires a re-scan to confirm compliance.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."
  
  findings_list=()
  check_results=()
  is_compliant=1 # Assume compliant

  # Check 1: RHEL Version Applicability
  rhel_version=$(get_rhel_version)
  check_results+=("->   RHEL Version: ${rhel_version}")
  if awk 'BEGIN {exit !('"$rhel_version"' >= 8.2)}'; then
    echo "          -> INFO: Rule is not applicable for RHEL version ${rhel_version} or newer."
    echo "          -> Check Results:"
    for result in "${check_results[@]}"; do echo "          $result"; done
    echo "STATUS: not_applicable"
    exit 0
  fi

  # Check 2: SELinux Status
  sestatus_output=$(sestatus 2>/dev/null)
  selinux_status=$(echo "$sestatus_output" | grep "SELinux status:" | awk '{print $3}')
  selinux_mode=$(echo "$sestatus_output" | grep "Current mode:" | awk '{print $3}')
  check_results+=("->   SELinux Status: ${selinux_status}")
  check_results+=("->   SELinux Mode: ${selinux_mode}")
  if [[ "$selinux_status" != "enabled" || "$selinux_mode" != "enforcing" ]]; then
    echo "          -> INFO: Rule is not applicable because SELinux is not enabled and in enforcing mode."
    echo "          -> Check Results:"
    for result in "${check_results[@]}"; do echo "          $result"; done
    echo "STATUS: not_applicable"
    exit 0
  fi

  # Check 3: pam_faillock non-default directory configuration
  tally_dir=$(grep -whr "pam_faillock.so.*dir=" /etc/pam.d/password-auth /etc/pam.d/system-auth | sed -n 's/.*dir=\([^ ]*\).*/\1/p' | head -n 1)
  
  if [[ -z "$tally_dir" ]]; then
    check_results+=("->   pam_faillock tally directory: Default (pam_faillock module not configured with 'dir' option)")
    echo "          -> INFO: Rule is not applicable because a non-default tally directory is not configured."
    echo "          -> Check Results:"
    for result in "${check_results[@]}"; do echo "          $result"; done
    echo "STATUS: not_applicable"
    exit 0
  fi

  check_results+=("->   pam_faillock tally directory: ${tally_dir}")

  # Check 4: Security context of the directory
  if [[ -d "$tally_dir" ]]; then
    current_context=$(ls -Zd "$tally_dir" | awk '{print $1}' | awk -F: '{print $3}')
    check_results+=("->   Security Context: ${current_context}")
    if [[ "$current_context" != "faillog_t" ]]; then
        is_compliant=0
        findings_list+=("-> Finding: The directory '${tally_dir}' has a security context of '${current_context}' instead of 'faillog_t'.")
    fi
  else
    is_compliant=0
    check_results+=("->   Security Context: NOT FOUND")
    findings_list+=("-> Finding: The configured tally directory '${tally_dir}' does not exist.")
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


