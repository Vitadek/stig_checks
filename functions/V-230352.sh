GROUP_ID="V-230352"
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
  if [[ ! -f "$profile_file" ]]; then
    echo "         -> ERROR: dconf profile file '$profile_file' not found. Cannot apply system-wide settings."
  else
    db_name=$(sudo grep -Po '(?<=^system-db:).+' "$profile_file")
    if [[ -z "$db_name" ]]; then
      echo "         -> ERROR: Could not determine dconf system database name from '$profile_file'."
    else
      # Create a dedicated override file to enforce the setting.
      override_file="/etc/dconf/db/${db_name}.d/01-session-idle"
      header="[org/gnome/desktop/session]"
      setting="idle-delay=uint32 900"
      
      echo "         -> Ensuring '$setting' is configured in '$override_file'."
      sudo mkdir -p "$(dirname "$override_file")"
      # Create or overwrite the file with the correct system-wide setting.
      printf "%s\n%s\n" "$header" "$setting" | sudo tee "$override_file" > /dev/null
      
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
  
  # Get the live gsettings value.
  gsettings_output=$(sudo gsettings get org.gnome.desktop.session idle-delay 2>/dev/null)
  
  if [[ -z "$gsettings_output" ]]; then
    finding_details="FINDING: The 'org.gnome.desktop.session idle-delay' setting is not configured."
  else
    # Expected format is "uint32 <value>"
    type=$(echo "$gsettings_output" | awk '{print $1}')
    value=$(echo "$gsettings_output" | awk '{print $2}')

    if [[ "$type" != "uint32" ]]; then
      finding_details="FINDING: The setting has an incorrect type. Expected 'uint32', found '${type}'."
    elif ! [[ "$value" =~ ^[0-9]+$ ]]; then
      finding_details="FINDING: The idle-delay value is not a number. Current setting: '${gsettings_output}'."
    # The value must be greater than 0 (enabled) and less than or equal to 900.
    elif [[ "$value" -gt 0 && "$value" -le 900 ]]; then
      is_compliant=1
    else
      finding_details="FINDING: The idle-delay is '${value}'. It must be greater than 0 and no more than 900 seconds (15 minutes)."
    fi
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "         -> OK: Session idle delay is set to a compliant value of '${value}' seconds."
    echo "STATUS: not_a_finding"
  else
    echo "         -> $finding_details"
    echo "STATUS: open"
  fi
fi
