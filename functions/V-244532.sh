#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify files in user home directories are group-owned by a group the user is a member of.
GROUP_ID="V-244532"

# --- Pre-flight Checks ---
# This script requires root privileges to inspect all user home directories.
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
  
  # Get local interactive users (UID >= 1000 and a home directory that exists)
  users_to_check=$(getent passwd | awk -F: '$3 >= 1000 && $6 ~ /^\/home/ {print $1}')

  for user in $users_to_check; do
    home_dir=$(getent passwd "$user" | cut -d: -f6)
    if [[ ! -d "$home_dir" ]]; then
      continue
    fi

    echo "          -> Applying fixes for user: ${user} in ${home_dir}"
    
    # Get the user's primary group
    primary_group=$(id -gn "$user")
    
    # Find all files/dirs not group-owned by a group the user is in and chgrp them
    # For simplicity in remediation, we set the group to the user's primary group.
    find "$home_dir" -not -gid "$(id -g "$user")" -exec chgrp "$primary_group" {} \;
  done
  
  echo "          -> Remediation logic has been executed."
  echo "  [WARNING] All files with incorrect group ownership were changed to the user's primary group."

  # After applying a fix, the status should be 'open' because it requires a re-scan to confirm compliance.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."
  
  findings_list=()
  check_results=()
  overall_compliant=1 # Assume compliant

  # Get local interactive users (UID >= 1000 and a home directory that exists)
  users_to_check=$(getent passwd | awk -F: '$3 >= 1000 && $6 ~ /^\/home/ {print $1}')
  
  if [ -z "$users_to_check" ]; then
      echo "          -> INFO: No local interactive users found to check."
      echo "STATUS: not_a_finding"
      exit 0
  fi
  
  check_results+=("->   Users checked: $(echo "$users_to_check" | tr '\n' ' ')")

  for user in $users_to_check; do
    home_dir=$(getent passwd "$user" | cut -d: -f6)
    if [[ ! -d "$home_dir" ]]; then
      continue
    fi

    user_groups=$(id -Gn "$user" | tr ' ' '\n')

    # Find files not owned by a group the user is a member of by piping find's output
    # directly to the while loop. This correctly handles null bytes.
    find "$home_dir" -print0 | while IFS= read -r -d '' file; do
        file_group=$(stat -c '%G' "$file")
        if ! echo "$user_groups" | grep -q -w "$file_group"; then
            overall_compliant=0
            findings_list+=("-> Finding: File '${file}' is group-owned by '${file_group}', but user '${user}' is not a member of that group.")
        fi
    done
  done
  
  # Report the final status based on the check.
  if [[ $overall_compliant -eq 1 ]]; then
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
    echo "STATUS: open"
  fi
fi


