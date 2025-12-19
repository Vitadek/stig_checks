GROUP_ID="V-230251"
if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."

  # --- Remediation Logic ---
  config_file="/etc/crypto-policies/back-ends/opensshserver.config"
  fips_macs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
  compliant_line="-oMACs=${fips_macs}"

  if [[ ! -f "$config_file" ]]; then
    echo "         -> ERROR: Configuration file '$config_file' not found. Cannot apply fix."
  else
    # Check if the MACs line exists, commented or not.
    if sudo grep -qi '^\s*#?\s*-oMACs=' "$config_file"; then
      # If it exists, replace the entire line to ensure it's correct and uncommented.
      echo "         -> Applying fix: Updating MACs setting in $config_file."
      sudo sed -i -E "s|^\s*#?\s*-oMACs=.*|${compliant_line}|i" "$config_file"
    else
      # If the line does not exist, append it.
      echo "         -> Applying fix: Adding MACs setting to $config_file."
      echo "${compliant_line}" | sudo tee -a "$config_file" > /dev/null
    fi
  fi
  
  echo "         -> Remediation logic has been executed."
  echo "  [WARNING] Review system changes to ensure correctness."
  echo "  [INFO]    Changes to crypto policies may require a system reboot to take full effect."

  # After applying a fix, the status should be 'open' because it requires a re-scan to confirm compliance.
  echo "STATUS: open"
else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  # --- Read-only check logic ---
  is_compliant=0 # Assume not compliant by default (0 = false)
  config_file="/etc/crypto-policies/back-ends/opensshserver.config"
  fips_macs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
  compliant_line="-oMACs=${fips_macs}"
  
  if [[ ! -f "$config_file" ]]; then
    finding_details="FINDING: SSH crypto policy file '${config_file}' does not exist."
  else
    # Grep for the active (uncommented) MACs line. The search is case-insensitive.
    current_setting=$(sudo grep -i '^\s*-oMACs=' "$config_file")

    if [[ -z "$current_setting" ]]; then
      finding_details="FINDING: The MACs setting is missing or commented out in '${config_file}'."
    elif [[ "$current_setting" == "$compliant_line" ]]; then
      is_compliant=1
    else
      finding_details="FINDING: The MACs setting is not configured correctly. It should be exactly:\n         ->          '${compliant_line}'\n         -> Current: '${current_setting}'"
    fi
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "         -> OK: SSH server is configured to use only FIPS-approved MACs in the correct order."
    echo "STATUS: not_a_finding"
  else
    echo -e "         -> ${finding_details}"
    echo "STATUS: open"
  fi
fi
