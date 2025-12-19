#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify the file integrity tool is configured to verify extended attributes.
GROUP_ID="V-230551"

# --- Pre-flight Checks ---
# This script requires root privileges to read aide.conf.
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
  echo "          -> The AIDE configuration file must be edited manually to ensure the 'xattrs' check"
  echo "          -> is included in all relevant rule definitions."
  echo "          -> 1. Locate your 'aide.conf' file (commonly in /etc/aide.conf)."
  echo "          -> 2. For each rule definition that is applied to files/directories (e.g., NORMAL, PERMS),"
  echo "          ->    ensure '+xattrs' is part of the definition."
  echo "          ->    Example: NORMAL = p+i+n+u+g+s+m+c+md5+acl+xattrs"
  echo "          -> 3. After updating the rules, you must re-initialize the AIDE database with 'aide --init'"
  echo "          ->    and replace the old database with the new one."

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

  # Check 1: Is AIDE installed?
  if ! command -v aide &> /dev/null; then
      echo "          -> INFO: AIDE command not found. This rule is not applicable."
      echo "          -> Check Results:"
      echo "          ->   AIDE Installed: No"
      echo "STATUS: not_applicable"
      exit 0
  fi
  check_results+=("->   AIDE Installed: Yes")

  # Check 2: Find aide.conf
  aide_conf_path=$(find / -name aide.conf 2>/dev/null | head -n 1)
  if [[ -z "$aide_conf_path" ]]; then
      is_compliant=0
      findings_list+=("-> Finding: 'aide.conf' file not found on the system.")
      check_results+=("->   aide.conf Path: Not Found")
  else
      check_results+=("->   aide.conf Path: ${aide_conf_path}")

      # Check 3: Analyze aide.conf for 'xattrs' usage
      # Get all rule definitions that DO NOT include 'xattrs'.
      # These are lines like 'RULENAME = ...'
      rules_without_xattrs=$(grep '^[A-Za-z0-9_]\+ \?=' "$aide_conf_path" | grep -v 'xattrs' | awk '{print $1}')

      # Now check if any of these non-compliant rules are actually used.
      for rule in $rules_without_xattrs; do
          # Check for selection lines (start with /) that use this specific rule.
          # We use -w for a whole word match to avoid partial matches.
          if grep -q -E "^/.*[[:space:]]+([^#]*\b${rule}\b.*)" "$aide_conf_path"; then
              is_compliant=0
              findings_list+=("-> Finding: Rule '${rule}' is used but does not check for xattrs.")
          fi
      done
      
      if [[ $is_compliant -eq 1 ]]; then
         check_results+=("->   xattrs Check: All applied rules appear to include the 'xattrs' directive.")
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

