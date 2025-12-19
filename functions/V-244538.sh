GROUP_ID="V-244538"
if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."

  # --- Remediation Logic ---
  # First, check if GNOME is installed. If not, this rule is not applicable.
  if ! rpm -q gnome-shell >/dev/null 2>&1; then
    echo "         -> [N/A] GNOME Desktop is not installed. This rule is Not Applicable."
    echo "STATUS: not_applicable"
    exit 0
  fi

  profile_file="/etc/dconf/profile/user"
  lock_setting="/org/gnome/desktop/session/idle-delay"
  
  if [[ ! -f "$profile_file" ]]; then
    echo "         -> [N/A] dconf profile file not found. System may not have a GUI. No action taken."
  else
    db_name=$(sudo grep -Po '(?<=^system-db:).+' "$profile_file")
    if [[ -z "$db_name" ]]; then
      echo "         -> ERROR: Could not determine dconf system database name from '$profile_file'."
    else
      lock_file="/etc/dconf/db/${db_name}.d/locks/session"
      echo "         -> Ensuring lock for '${lock_setting}' exists in '${lock_file}'."
      sudo mkdir -p "$(dirname "$lock_file")"
      
      # Add the lock setting to the file if it's not already there.
      if ! sudo grep -qFx "${lock_setting}" "${lock_file}" 2>/dev/null; then
        echo "${lock_setting}" | sudo tee -a "${lock_file}" > /dev/null
      fi
      
      echo "         -> Updating dconf database."
      sudo dconf update
      echo "         -> Remediation logic has been executed."
    fi
  fi

  echo "  [WARNING] Review system changes to ensure correctness."
  
  # After applying a fix, the status should be 'open' because it requires a re-scan to confirm compliance.
  echo "STATUS: open"
else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  # --- Read-only check logic ---
  # First, check if GNOME is installed. If not, this rule is not applicable.
  if ! rpm -q gnome-shell >/dev/null 2>&1; then
    echo "         -> [N/A] GNOME Desktop is not installed. This rule is Not Applicable."
    echo "STATUS: not_applicable"
    exit 0
  fi

  is_compliant=0 # Assume not compliant by default (0 = false)
  profile_file="/etc/dconf/profile/user"
  lock_setting="/org/gnome/desktop/session/idle-delay"
  
  if [[ ! -f "$profile_file" ]]; then
    # If dconf isn't configured, a GUI is likely not in use.
    is_compliant=1
    finding_details="OK: dconf profile file not found. Rule is Not Applicable as a GUI is likely not installed."
  else
    db_name=$(sudo grep -Po '(?<=^system-db:).+' "$profile_file")
    if [[ -z "$db_name" ]]; then
      finding_details="FINDING: Could not determine dconf system database name from '$profile_file'."
    else
      locks_dir="/etc/dconf/db/${db_name}.d/locks"
      if [[ ! -d "$locks_dir" ]]; then
        finding_details="FINDING: dconf locks directory '${locks_dir}' does not exist."
      # Use grep -r (recursive) to search for the lock in any file within the locks directory.
      elif sudo grep -qr "${lock_setting}" "$locks_dir"; then
        is_compliant=1
      else
        finding_details="FINDING: The setting '${lock_setting}' is not locked in any file under '${locks_dir}'."
      fi
    fi
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "         -> ${finding_details:-OK: The idle-delay setting is correctly locked.}"
    echo "STATUS: not_a_finding"
  else
    echo "         -> $finding_details"
    echo "STATUS: open"
  fi
fi
