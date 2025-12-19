#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify the RHEL 8 "fapolicyd" employs a deny-all, permit-by-exception policy.
GROUP_ID="V-244546"

# --- Pre-flight Checks ---
# This script requires root privileges to read fapolicyd config and run remediation.
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

  if [[ ! -f /etc/fapolicyd/fapolicyd.conf ]]; then
     echo "          -> 'fapolicyd' is not installed or config file is missing. No remediation applied."
  else
    # Ensure permissive mode is off (set to 0)
    if grep -q "^\s*permissive\s*=" /etc/fapolicyd/fapolicyd.conf; then
        sed -i 's/^\s*permissive\s*=.*/permissive = 0/' /etc/fapolicyd/fapolicyd.conf
        echo "          -> Applying fix: Set 'permissive = 0' in /etc/fapolicyd/fapolicyd.conf."
    else
        echo "permissive = 0" >> /etc/fapolicyd/fapolicyd.conf
        echo "          -> Applying fix: Added 'permissive = 0' to /etc/fapolicyd/fapolicyd.conf."
    fi
    echo "          -> Remediation logic for 'permissive' setting has been executed."
    echo "  [WARNING] The fapolicyd rules must be manually configured to ensure a deny-all policy."
    echo "  [WARNING] Incorrectly configured rules may lock out the system."
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

  # Check 1: fapolicyd installation
  if ! rpm -q fapolicyd &>/dev/null; then
    echo "          -> INFO: Rule is not applicable because 'fapolicyd' is not installed."
    echo "STATUS: not_applicable"
    exit 0
  fi
  check_results+=("->   fapolicyd package: installed")

  # Check 2: Permissive mode
  permissive_setting=$(grep "^\s*permissive\s*=" /etc/fapolicyd/fapolicyd.conf | awk -F= '{gsub(/ /,"",$2); print $2}')
  check_results+=("->   Permissive Setting: ${permissive_setting:-Not Set}")
  if [[ "$permissive_setting" != "0" ]]; then
    is_compliant=0
    findings_list+=("-> Finding: 'fapolicyd' is not in enforcing mode (permissive is not 0).")
  fi

  # Check 3: Deny-all rule
  rhel_version=$(get_rhel_version)
  check_results+=("->   RHEL Version: ${rhel_version}")
  major_version=$(echo "$rhel_version" | cut -d. -f1)
  minor_version=$(echo "$rhel_version" | cut -d. -f2)

  rules_file=""
  if [[ "$major_version" -eq 8 && "$minor_version" -ge 5 ]]; then
    rules_file="/etc/fapolicyd/compiled.rules"
  else
    rules_file="/etc/fapolicyd/fapolicyd.rules"
  fi
  
  check_results+=("->   Rules file checked: ${rules_file}")

  if [[ ! -f "$rules_file" ]]; then
    is_compliant=0
    check_results+=("->   Last Rule: File not found")
    findings_list+=("-> Finding: The rules file '${rules_file}' does not exist.")
  else
    last_rule=$(grep -v -e '^\s*#' -e '^\s*$' "$rules_file" | tail -n 1)
    check_results+=("->   Last Rule found: '${last_rule}'")
    
    # Normalize by removing all whitespace and comparing
    normalized_rule=$(echo "$last_rule" | tr -d '[:space:]')
    expected_rule="denyperm=anyall:all"
    
    if [[ "$normalized_rule" != "$expected_rule" ]]; then
        is_compliant=0
        findings_list+=("-> Finding: The last rule is not a 'deny all' rule.")
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

