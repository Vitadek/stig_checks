#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify the OS implements DOD-approved encryption for remote access sessions.
GROUP_ID="V-230223"

# --- Pre-flight Checks ---
# This script requires root privileges to check and set crypto policies.
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

  current_policy=$(update-crypto-policies --show)
  
  if [[ "$current_policy" != "FIPS" ]]; then
      echo "          -> Applying fix: Enabling FIPS mode with 'fips-mode-setup --enable'."
      # Note: This command can have interactive prompts, which we can't handle here.
      # The user must run this with awareness.
      fips-mode-setup --enable
      echo "          -> Remediation logic has been executed."
      echo "  [WARNING] A reboot is required for these changes to take full effect."
  else
      echo "          -> No remediation needed. The current policy is already FIPS."
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
  is_compliant=1 # Assume compliant

  current_policy=$(update-crypto-policies --show)
  check_results+=("->   Current Systemwide Crypto Policy: ${current_policy}")

  # Main policy must be FIPS
  if ! echo "$current_policy" | grep -q "^FIPS"; then
      is_compliant=0
      findings_list+=("-> Finding: The main cryptographic policy is not set to 'FIPS'.")
  else
      # Check for subpolicies
      subpolicies=$(echo "$current_policy" | cut -d':' -f2-)
      if [[ -n "$subpolicies" && "$subpolicies" != "$current_policy" ]]; then
          IFS=':' read -ra subpolicy_array <<< "$subpolicies"
          for sub in "${subpolicy_array[@]}"; do
              case "$sub" in
                  "AD-SUPPORT")
                      is_compliant=0 # Requires manual check
                      findings_list+=("-> Finding: Manual review required. The 'AD-SUPPORT' subpolicy is enabled. Verify this is documented with the ISSO as an operational requirement.")
                      ;;
                  "NO-ENFORCE-EMS")
                      is_compliant=0 # Requires manual check
                      findings_list+=("-> Finding: Manual review required. The 'NO-ENFORCE-EMS' subpolicy is enabled. Verify this is documented with the ISSO as an operational requirement.")
                      ;;
                  *)
                      is_compliant=0
                      findings_list+=("-> Finding: An unauthorized subpolicy module ('${sub}') is included in the cryptographic policy.")
                      ;;
              esac
          done
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

