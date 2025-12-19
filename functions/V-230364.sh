GROUP_ID="V-230364"
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
  # Add the root user to the list to be checked.
  user_list+=$'\n'root

  # Check and fix each user's min password age.
  for user in $user_list; do
    # Skip empty lines that might result from the list creation
    if [[ -z "$user" ]]; then continue; fi

    min_age=$(sudo grep "^${user}:" /etc/shadow | cut -d: -f4)
    
    if [[ -z "$min_age" ]]; then
      continue
    fi
    
    # If min_age is less than 1, apply the fix.
    if [[ "$min_age" -lt 1 ]]; then
      echo "         -> Applying fix: Setting minimum password age for user '${user}' to 1 day."
      sudo chage -m 1 "$user"
      changes_made=1
    fi
  done

  if [[ $changes_made -eq 0 ]]; then
    echo "         -> No remediation needed. All checked users are compliant."
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
  user_details="Displaying all non-system users (and root) and their current minimum password age:"

  # Determine the minimum UID for non-system accounts from login.defs, default to 1000.
  min_uid=$(grep '^\s*UID_MIN' /etc/login.defs | awk '{print $2}')
  if [[ -z "$min_uid" ]]; then
    min_uid=1000
  fi

  # Get a list of all users with a UID >= min_uid and a login shell.
  user_list=$(awk -v min="$min_uid" -F: '($3 >= min) && ($7!~/(nologin|false)$/) {print $1}' /etc/passwd)
  # Add the root user to the list to be checked.
  user_list+=$'\n'root

  # Check each user's min password age in /etc/shadow.
  for user in $user_list; do
    # Skip empty lines that might result from the list creation
    if [[ -z "$user" ]]; then continue; fi
    
    min_age=$(sudo grep "^${user}:" /etc/shadow | cut -d: -f4)
    
    if [[ -z "$min_age" ]]; then
      min_age="N/A"
    fi
    
    # Append user details to the output string for display.
    user_details+="\n            - User: ${user}, Min Age: ${min_age}"

    # A finding occurs if min_age is less than 1.
    if [[ "$min_age" != "N/A" && "$min_age" -lt 1 ]]; then
      is_compliant=0 # Set to false
      non_compliant_users+=" $user(age:${min_age})"
    fi
  done
  
  # Print the detailed list of all users and their settings.
  echo -e "         ${user_details}"
  echo "" # Add a blank line for readability

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "         -> OK: All checked accounts have a compliant minimum password age (>= 1 day)."
    echo "STATUS: not_a_finding"
  else
    finding_details="FINDING: The following user(s) have a minimum password age of less than 1 day:"
    echo "         -> ${finding_details}${non_compliant_users}"
    echo "STATUS: open"
  fi
fi

