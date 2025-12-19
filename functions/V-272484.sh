#!/bin/bash

# --- Configuration ---
GROUP_ID="V-272484"
# This script no longer uses a designated group. Instead, it identifies all
# non-system users (UID >= 1000) with /bin/bash as their shell and applies
# the sudo rule to them individually.
#
# File where the fix will be applied. Naming convention is important for sudo.
FIX_FILE="/etc/sudoers.d/99-stig-selinux-user-contexts"

# --- Pre-flight Checks ---
# This script needs to read /etc/sudoers and write to /etc/sudoers.d,
# which requires root privileges.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Helper Functions ---

# get_bash_users:
# Parses /etc/passwd to find all regular user accounts that use /bin/bash.
# It filters for UIDs >= 1000 to exclude system accounts.
get_bash_users() {
  awk -F: '$3 >= 1000 && $7 == "/bin/bash" {print $1}' /etc/passwd
}

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Checking rule $GROUP_ID for all bash users..."
  
  # Array to hold the configuration lines that are missing and need to be added.
  configs_to_add=()

  # Iterate over each user found by the get_bash_users function.
  while read -r user; do
    required_config_for_user="$user ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL"
    
    # Check if the exact configuration line for this user already exists.
    # -r: recursive, -s: silent, -h: no filename, -q: quiet (exit code only)
    if ! grep -rshq "$required_config_for_user" /etc/sudoers /etc/sudoers.d/; then
      echo "          -> MISSING configuration for user: $user"
      configs_to_add+=("$required_config_for_user")
    else
      echo "          -> OK: Configuration found for user: $user"
    fi
  done < <(get_bash_users)

  # If the array of missing configs has items in it, apply the fix.
  if [[ ${#configs_to_add[@]} -gt 0 ]]; then
    echo "          -> Applying fixes by adding missing configurations to $FIX_FILE..."
    # Append all missing configurations to the fix file.
    printf "%s\n" "${configs_to_add[@]}" >> "$FIX_FILE"
    
    # Sudoers files require strict permissions to be read by the system.
    chmod 440 "$FIX_FILE"
    echo "          -> Set permissions on $FIX_FILE to 440."
    echo ""
    echo "  [WARNING] The required rules have been added. You should now manually"
    echo "            review /etc/sudoers and other files in /etc/sudoers.d"
    echo "            to ensure there are no conflicting sudo rules."
    echo ""
    # After applying, the finding is now considered open until re-scanned.
    echo "STATUS: open"
  else
    echo "          -> All users are correctly configured. No changes made."
    # Since everything was correct, it's not a finding.
    echo "STATUS: not_a_finding"
  fi

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking rule $GROUP_ID for all bash users..."
  
  # Flag to track if we find any misconfigurations.
  findings_found=0
  
  # Iterate over each user.
  while read -r user; do
    required_config_for_user="$user ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL"
    
    # Check if the config exists for the user.
    if ! grep -rshq "$required_config_for_user" /etc/sudoers /etc/sudoers.d/; then
      echo "          -> FINDING: SELinux context elevation rule is MISSING for user: $user"
      findings_found=1
    fi
  done < <(get_bash_users)

  # Report the final status based on the flag.
  if [[ $findings_found -eq 0 ]]; then
    echo "          -> OK: All bash users are configured correctly."
    echo "STATUS: not_a_finding"
  else
    # If any user is missing the config, the entire check is a finding.
    echo "STATUS: open"
  fi
fi

