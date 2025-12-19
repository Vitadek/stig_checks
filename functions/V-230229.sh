#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify RHEL 8 has a valid DoD root CA for PKI-based authentication.
GROUP_ID="V-230229"

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
  echo "          -> MANUAL REMEDIATION REQUIRED:"
  echo "          -> A valid DoD root CA certificate must be obtained and installed."
  echo "          -> 1. Obtain a valid copy of the DoD root CA file from the PKI CA certificate"
  echo "          ->    bundle at cyber.mil."
  echo "          -> 2. Copy the certificate into the following file, creating the directories"
  echo "          ->    if necessary: /etc/sssd/pki/sssd_auth_ca_db.pem"
  echo "          -> 3. Ensure the file permissions are appropriate (e.g., 644)."
  
  # After providing manual instructions, the status must be 'open' as manual action is needed.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  findings_list=()
  check_results=()
  # This check requires manual verification, so it starts as non-compliant.
  is_compliant=0
  findings_list+=("-> Finding: Manual review required. If the system does not use PKI-based authentication (e.g., uses an approved alternate MFA method), this may be Not Applicable.")

  cert_file="/etc/sssd/pki/sssd_auth_ca_db.pem"

  # Check 1: Certificate file existence
  if [[ ! -f "$cert_file" ]]; then
      is_compliant=0
      findings_list+=("-> Finding: The root CA certificate file '${cert_file}' was not found.")
      check_results+=("->   Certificate File: Not Found")
  else
      check_results+=("->   Certificate File: Found at ${cert_file}")

      # Check 2: Certificate Issuer
      issuer=$(openssl x509 -in "$cert_file" -noout -issuer 2>/dev/null | sed 's/issuer=//')
      if [[ -z "$issuer" ]]; then
          is_compliant=0
          findings_list+=("-> Finding: Could not read issuer from certificate '${cert_file}'. It may be invalid or corrupted.")
          check_results+=("->   Certificate Issuer: Unable to read")
      else
          check_results+=("->   Certificate Issuer: ${issuer}")
          if ! echo "$issuer" | grep -q -i "DoD"; then
              is_compliant=0
              findings_list+=("-> Finding: The certificate issuer does not appear to be a DoD root CA.")
          fi
      fi
      
      # Check 3: Certificate Validity (Expiration Date)
      enddate_str=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
      if [[ -z "$enddate_str" ]]; then
          is_compliant=0
          findings_list+=("-> Finding: Could not read expiration date from certificate '${cert_file}'.")
          check_results+=("->   Certificate Expiration: Unable to read")
      else
          check_results+=("->   Certificate Expiration: ${enddate_str}")
          enddate_seconds=$(date -d "$enddate_str" +%s)
          now_seconds=$(date +%s)
          if [[ "$enddate_seconds" -lt "$now_seconds" ]]; then
              is_compliant=0
              findings_list+=("-> Finding: The root CA certificate has expired.")
          fi
      fi
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    # This state is unlikely because of the manual check, but included for completeness.
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
    echo "STATUS: not_reviewed"
  fi
fi

