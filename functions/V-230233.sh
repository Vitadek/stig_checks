OUP_ID="V-230233"
if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."

  # --- Remediation Logic ---
  config_file="/etc/login.defs"
  compliant_line="SHA_CRYPT_MIN_ROUNDS 100000"
  
  # Check if SHA_CRYPT_MIN_ROUNDS is already defined (commented or not).
  if sudo grep -qi '^\s*#?\s*SHA_CRYPT_MIN_ROUNDS' "$config_file"; then
    # If it exists, replace the line to ensure it is set correctly and uncommented.
    echo "         -> Applying fix: Updating SHA_CRYPT_MIN_ROUNDS in $config_file."
    sudo sed -i -E "s/^\s*#?\s*SHA_CRYPT_MIN_ROUNDS.*/${compliant_line}/" "$config_file"
  else
    # If it does not exist, append it to the file.
    echo "         -> Applying fix: Adding SHA_CRYPT_MIN_ROUNDS to $config_file."
    echo "${compliant_line}" | sudo tee -a "$config_file" > /dev/null
  fi

  echo "         -> Remediation logic has been executed."
  echo "  [WARNING] Review system changes to ensure correctness."

  # After applying a fix, the status should be 'open' because it requires a re-scan to confirm compliance.
  echo "STATUS: open"
else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  # --- Read-only check logic ---
  is_compliant=0 # Assume not compliant by default (0 = false)
  config_file="/etc/login.defs"
  required_rounds=100000
  finding_details=""

  # Get the active (uncommented) values.
  min_rounds=$(sudo grep -E '^\s*SHA_CRYPT_MIN_ROUNDS' "$config_file" | awk '{print $2}')
  max_rounds=$(sudo grep -E '^\s*SHA_CRYPT_MAX_ROUNDS' "$config_file" | awk '{print $2}')

  if [[ -n "$min_rounds" && -n "$max_rounds" ]]; then
    # Both are set, check if the higher of the two is compliant.
    highest_val=$(( min_rounds > max_rounds ? min_rounds : max_rounds ))
    if [[ "$highest_val" -ge "$required_rounds" ]]; then
      is_compliant=1
    else
      finding_details="FINDING: Both MIN and MAX rounds are set, but the highest value ($highest_val) is less than ${required_rounds}."
    fi
  elif [[ -n "$min_rounds" ]]; then
    # Only MIN is set, check if it is compliant.
    if [[ "$min_rounds" -ge "$required_rounds" ]]; then
      is_compliant=1
    else
      finding_details="FINDING: SHA_CRYPT_MIN_ROUNDS is set to ${min_rounds}, which is less than ${required_rounds}."
    fi
  elif [[ -n "$max_rounds" ]]; then
    # Only MAX is set, check if it is compliant.
    if [[ "$max_rounds" -ge "$required_rounds" ]]; then
      is_compliant=1
    else
      finding_details="FINDING: SHA_CRYPT_MAX_ROUNDS is set to ${max_rounds}, which is less than ${required_rounds}."
    fi
  else
    # Neither is set.
    finding_details="FINDING: Neither SHA_CRYPT_MIN_ROUNDS nor SHA_CRYPT_MAX_ROUNDS is set."
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "         -> OK: Password hashing rounds are configured to a compliant value (>= ${required_rounds})."
    echo "STATUS: not_a_finding"
  else
    echo "         -> $finding_details"
    echo "STATUS: open"
  fi
fi
