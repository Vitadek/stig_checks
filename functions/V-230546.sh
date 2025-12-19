GROUP_ID="V-230546"
if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."

  # --- Implement remediation logic here ---
  # Use a clear, single-quoted regex to avoid shell expansion issues.
  # This finds lines starting with optional '#' and whitespace, the key, and an '='.
  REGEX_PATTERN='^\s*#?\s*kernel\.yama\.ptrace_scope\s*='
  # The final, compliant line to be written.
  REPLACEMENT_LINE='kernel.yama.ptrace_scope = 1'
  target_config_file="/etc/sysctl.d/99-sysctl.conf"

  search_paths=(
    "/etc/sysctl.conf"
    "/etc/sysctl.d"
    "/run/sysctl.d"
    "/usr/local/lib/sysctl.d"
    "/usr/lib/sysctl.d"
    "/lib/sysctl.d"
  )

  # Find all files that contain the setting (commented or uncommented).
  files_with_setting=$(sudo grep -sRl --include='*.conf' "${REGEX_PATTERN}" "${search_paths[@]}" 2>/dev/null)

  if [[ -n "$files_with_setting" ]]; then
    # If settings exist, iterate through each file and enforce the compliant value.
    echo "         -> Applying fix: Found existing configurations. Correcting all instances to '${REPLACEMENT_LINE}'."
    for file in $files_with_setting; do
      echo "            - Modifying $file"
      # The sed command now uses the same robust regex to find and replace the entire line.
      sudo sed -i -E "s|${REGEX_PATTERN}.*|${REPLACEMENT_LINE}|" "$file"
    done
  else
    # If the setting is not found in any file, add it to a standard override file.
    echo "         -> Applying fix: No existing setting found. Adding '${REPLACEMENT_LINE}' to ${target_config_file}."
    sudo mkdir -p "$(dirname "$target_config_file")"
    echo "${REPLACEMENT_LINE}" | sudo tee -a "${target_config_file}" > /dev/null
  fi

  # Reload sysctl settings to apply the change.
  echo "         -> Reloading system sysctl settings."
  if sudo sysctl --system >/dev/null 2>&1; then
      echo "         -> Remediation logic has been executed."
  else
      echo "  [ERROR]  Failed to reload sysctl settings. Manual intervention may be required."
  fi
  echo "  [WARNING] Review system changes to ensure correctness."

  echo "STATUS: open"
else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  # --- Implement read-only check logic here ---
  is_compliant=0 # Assume not compliant by default.
  finding_details=""

  # 1. Check the live kernel parameter value.
  live_value=$(sudo sysctl -n kernel.yama.ptrace_scope 2>/dev/null)
  if [[ "$live_value" != "1" ]]; then
    finding_details="FINDING: The live kernel value for kernel.yama.ptrace_scope is '$live_value' instead of '1'."
  else
    # 2. Check all persistent configuration files for compliance.
    search_paths=(
      "/etc/sysctl.conf"
      "/etc/sysctl.d"
      "/run/sysctl.d"
      "/usr/local/lib/sysctl.d"
      "/usr/lib/sysctl.d"
      "/lib/sysctl.d"
    )
    
    all_settings=$(sudo grep -sRh --include='*.conf' '^\s*kernel\.yama\.ptrace_scope\s*=' "${search_paths[@]}" 2>/dev/null)

    if [[ -z "$all_settings" ]]; then
      finding_details="FINDING: The setting 'kernel.yama.ptrace_scope = 1' is not configured to persist across reboots."
    else
      conflicting_settings=$(echo "$all_settings" | grep -v '^\s*kernel\.yama\.ptrace_scope\s*=\s*1\s*')
      
      if [[ -n "$conflicting_settings" ]]; then
        first_conflict=$(echo "$conflicting_settings" | head -n1)
        finding_details="FINDING: A non-compliant setting was found: '${first_conflict}'. All active settings must be '1'."
      else
        is_compliant=1
      fi
    fi
  fi

  if [[ $is_compliant -eq 1 ]]; then
    echo "         -> OK: kernel.yama.ptrace_scope is active and all persistent configurations are correctly set to '1'."
    echo "STATUS: not_a_finding"
  else
    echo "         -> $finding_details"
    echo "STATUS: open"
  fi
fi
