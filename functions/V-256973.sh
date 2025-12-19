#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Confirm Red Hat package-signing keys are installed on the system and verify their fingerprints match vendor values.
GROUP_ID="V-256973"

# --- Pre-flight Checks ---
# This script requires root privileges to check GPG keys.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Helper Variables ---
KEY_FILE="/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
# Fingerprints are stripped of spaces for easier programmatic comparison.
EXPECTED_RELEASE_FINGERPRINT="567E347AD0044ADE55BA8A5F199E2F91FD431D51"
EXPECTED_AUX_FINGERPRINT="6A6AA7C97C8890AEC6AEBFE2F76F66C3D4082792"
RELEASE_KEY_NAME="Red Hat, Inc. (release key 2)"
AUX_KEY_NAME="Red Hat, Inc. (auxiliary key)"

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."
  echo "          -> This rule requires manual remediation."
  echo "          -> Automatic remediation is not available because the script cannot automatically locate the RHEL installation media."
  echo "          -> Please perform the following steps:"
  echo "          -> 1. Mount the RHEL 8 installation disc or image (e.g., to /media/cdrom)."
  echo "          -> 2. Copy the GPG key file onto the system:"
  echo "          ->    sudo cp /media/cdrom/RPM-GPG-KEY-redhat-release /etc/pki/rpm-gpg/"
  echo "          -> 3. Import the GPG keys into the system keyring:"
  echo "          ->    sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
  echo "          -> Remediation instructions have been displayed."

  # After applying a fix, the status should be 'open' because it requires a re-scan to confirm compliance.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."
  
  findings_list=()
  is_compliant=1 # Assume compliant

  # 1. Check if required keys are imported
  installed_keys=$(rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey)
  if ! echo "$installed_keys" | grep -qF "$RELEASE_KEY_NAME"; then
    is_compliant=0
    findings_list+=("-> Finding: GPG key '${RELEASE_KEY_NAME}' is not installed.")
  fi
  if ! echo "$installed_keys" | grep -qF "$AUX_KEY_NAME"; then
    is_compliant=0
    findings_list+=("-> Finding: GPG key '${AUX_KEY_NAME}' is not installed.")
  fi

  # 2. Check if key file exists
  if [[ ! -f "$KEY_FILE" ]]; then
    is_compliant=0
    findings_list+=("-> Finding: GPG key file '${KEY_FILE}' is missing.")
  else
    # 3. If file exists, check fingerprints and their association with the correct keys.
    release_fingerprint_ok=0
    aux_fingerprint_ok=0

    # Use awk to parse the gpg output. It allows us to associate fingerprints with UIDs.
    # The script looks for a UID line, and if it matches, it checks the fingerprint
    # that was stored from the preceding "Key fingerprint" line.
    # Using index() instead of ~ to avoid regex interpretation of key names.
    gpg_check_output=$(gpg -q --with-fingerprint "$KEY_FILE" 2>/dev/null | awk \
      -v release_fp="$EXPECTED_RELEASE_FINGERPRINT" \
      -v aux_fp="$EXPECTED_AUX_FINGERPRINT" \
      -v release_name="$RELEASE_KEY_NAME" \
      -v aux_name="$AUX_KEY_NAME" '
        /Key fingerprint =/ {
            # Remove prefix and all spaces, then store the fingerprint
            gsub(/.*= /, "");
            gsub(/[[:space:]]/, "");
            current_fp=$0
        }
        index($0, release_name) {
            if (current_fp == release_fp) {
                print "release_ok"
            }
        }
        index($0, aux_name) {
            if (current_fp == aux_fp) {
                print "aux_ok"
            }
        }
    ')

    if echo "$gpg_check_output" | grep -q "release_ok"; then
        release_fingerprint_ok=1
    fi
    if echo "$gpg_check_output" | grep -q "aux_ok"; then
        aux_fingerprint_ok=1
    fi
    
    if [[ $release_fingerprint_ok -eq 0 ]]; then
        is_compliant=0
        findings_list+=("-> Finding: GPG key for '${RELEASE_KEY_NAME}' has an incorrect or missing fingerprint.")
    fi
    if [[ $aux_fingerprint_ok -eq 0 ]]; then
        is_compliant=0
        findings_list+=("-> Finding: GPG key for '${AUX_KEY_NAME}' has an incorrect or missing fingerprint. It should be noted, that this usually generates a false open, currently working on a fix.")
    fi
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "          -> OK: System is compliant with rule $GROUP_ID."
    echo "STATUS: not_a_finding"
  else
    echo "          -> FINDING: System is NOT compliant with rule $GROUP_ID."
    for finding in "${findings_list[@]}"; do
        echo "          $finding"
    done
    echo "STATUS: open"
  fi
fi


