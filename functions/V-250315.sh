#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify SELinux context for a non-default pam_faillock tally directory on RHEL 8.2+.
GROUP_ID="V-250315"

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

  # Find the non-default tally directory from faillock.conf.
  tally_dir=$(grep -wh "^\s*dir\s*=" /etc/security/faillock.conf | awk -F= '{gsub(/ /,"",$2); print $2}' | head -n 1)

  if [[ -n "$tally_dir" ]]; then
    echo "          -> Applying fix: Setting SELinux context for '${tally_dir}'."
    if [[ ! -d "$tally_dir" ]]; then
        echo "          -> Creating directory: ${tally_dir}"
        mkdir -p "$tally_dir"
    fi
    semanage fcontext -a -t faillog_t "${tally_dir}(/.*)?"
    restorecon -R -v "$tally_dir"
    echo "          -> Remediation logic has been executed."
  else
    echo "          -> No non-default 'dir' option found in /etc/security/faillock.conf. No remediation needed."
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
  
  major_version=$(echo "$rhel_version" | cut -d. -f1)
  minor_version=$(echo "$rhel_version" | cut -d. -f2)

  if [[ "$major_version" -eq 8 && "$minor_version" -lt 2 ]]; then
    echo "          -> INFO: Rule is not applicable for RHEL version ${rhel_version} (requires 8.2 or newer)."
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
  tally_dir=$(grep -wh "^\s*dir\s*=" /etc/security/faillock.conf | awk -F= '{gsub(/ /,"",$2); print $2}' | head -n 1)
  
  if [[ -z "$tally_dir" ]]; then
    check_results+=("->   pam_faillock tally directory: Default (not configured in /etc/security/faillock.conf)")
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


