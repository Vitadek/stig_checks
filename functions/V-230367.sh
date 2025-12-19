GROUP_ID="V-230367"
if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."

  # --- Remediation Logic ---
  changes_made=0 # Flag to track if any changes were applied

  # Determine the minimum UID for non-system accounts from login.defs, default to 1000.
  min_uid=$(grep '^\s*UID_MIN' /etc/login.defs | awk '{print $2}')
  if [[ -z "$min_uid" ]]; then
    min_uid=1000
  fi

  # Get a list of all users with a UID >= min_uid and a login shell.
  user_list=$(awk -v min="$min_uid" -F: '($3 >= min) && ($7!~/(nologin|false)$/) {print $1}' /etc/passwd)

  # Check and fix each user's max password age.
  for user in $user_list; do
    max_age=$(sudo grep "^${user}:" /etc/shadow | cut -d: -f5)
    
    if [[ -z "$max_age" ]]; then
      continue
    fi
    
    # If max_age is greater than 60 or has no limit (<=0), apply the fix.
    if [[ "$max_age" -gt 60 || "$max_age" -le 0 ]]; then
      echo "         -> Applying fix: Setting max password age for user '${user}' to 60 days."
      sudo chage -M 60 "$user"
      changes_made=1
    fi
  done

  if [[ $changes_made -eq 0 ]]; then
    echo "         -> No remediation needed. All users are compliant."
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
  is_compliant=1 # Assume compliant by default (1 = true)
  non_compliant_users=""

  # Determine the minimum UID for non-system accounts from login.defs, default to 1000.
  min_uid=$(grep '^\s*UID_MIN' /etc/login.defs | awk '{print $2}')
  if [[ -z "$min_uid" ]]; then
    min_uid=1000
  fi

  # Get a list of all users with a UID >= min_uid and a login shell.
  user_list=$(awk -v min="$min_uid" -F: '($3 >= min) && ($7!~/(nologin|false)$/) {print $1}' /etc/passwd)

  # Check each user's max password age in /etc/shadow.
  for user in $user_list; do
    max_age=$(sudo grep "^${user}:" /etc/shadow | cut -d: -f5)
    
    if [[ -z "$max_age" ]]; then
      continue
    fi
    
    # A finding occurs if max_age is greater than 60 or less than or equal to 0.
    if [[ "$max_age" -gt 60 || "$max_age" -le 0 ]]; then
      is_compliant=0 # Set to false
      non_compliant_users+=" $user(age:${max_age})"
    fi
  done

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "         -> OK: All non-system accounts have a compliant maximum password age (1-60 days)."
    echo "STATUS: not_a_finding"
  else
    finding_details="FINDING: The following user(s) have a maximum password age greater than 60 days or no limit set:"
    echo "         -> ${finding_details}${non_compliant_users}"
    echo "STATUS: open"
  fi
fi
