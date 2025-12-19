GROUP_ID="V-244525"
if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."

  # --- Implement remediation logic here ---
  config_file="/etc/ssh/sshd_config"

  # Check if ClientAliveInterval is already configured (commented or not).
  if sudo grep -qi '^\s*#?\s*clientaliveinterval' "$config_file"; then
    # If the line exists, modify it to be compliant. This sed command finds
    # the line and replaces it with the correct, uncommented setting.
    echo "         -> Applying fix: Setting ClientAliveInterval to 600 in $config_file."
    sudo sed -i -E 's/^\s*#?\s*(ClientAliveInterval\s+).*/ClientAliveInterval 600/i' "$config_file"
  else
    # If the line does not exist, append it to the end of the file.
    echo "         -> Applying fix: Adding 'ClientAliveInterval 600' to $config_file."
    echo "" | sudo tee -a "$config_file" > /dev/null
    echo "ClientAliveInterval 600" | sudo tee -a "$config_file" > /dev/null
  fi

  echo "         -> Remediation logic has been executed."
  echo "  [WARNING] Review system changes to ensure correctness."
  echo "  [INFO]    Restart the sshd service for changes to take effect: sudo systemctl restart sshd.service"

  # After applying a fix, the status should be 'open' because it requires a re-scan to confirm compliance.
  echo "STATUS: open"
else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  # --- Implement read-only check logic here ---
  is_compliant=0 # Assume not compliant by default (0 = false)
  
  # Use sshd -T to get the effective configuration value. This is the most reliable method
  # as it reflects the final value sshd will use, accounting for includes and overrides.
  effective_value=$(sudo /usr/sbin/sshd -T | grep -i '^clientaliveinterval' | awk '{print $2}' 2>/dev/null)

  # If the value is not set, the default is 0 (disabled), which is non-compliant.
  if [[ -z "$effective_value" ]]; then
      effective_value=0
  fi

  # Check if the effective value is within the compliant range (greater than 0 and less than or equal to 600).
  if [[ "$effective_value" -gt 0 && "$effective_value" -le 600 ]]; then
      is_compliant=1
      check_details="OK: Effective ClientAliveInterval is '$effective_value', which is within the compliant range (1-600)."
  else
      is_compliant=0
      check_details="FINDING: Effective ClientAliveInterval is '$effective_value'. It must be set to a value greater than 0 and less than or equal to 600."
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "         -> ${check_details}"
    echo "STATUS: not_a_finding"
  else
    echo "         -> ${check_details}"
    echo "STATUS: open"
  fi
fi
