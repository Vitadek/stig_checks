#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify file systems that contain user home directories are mounted with the "noexec" option.
GROUP_ID="V-230302"

# --- Pre-flight Checks ---
# This script requires root privileges to read system files.
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
  echo "          -> MANUAL REMEDIATION REQUIRED:"
  echo "          -> The '/etc/fstab' file must be manually edited to add the 'noexec' option"
  echo "          -> to any filesystem that contains local interactive user home directories."
  echo "          -> WARNING: Do NOT add 'noexec' to the root ('/') filesystem."
  echo "          -> 1. Identify the filesystem for user homes (e.g., /home)."
  echo "          -> 2. Edit '/etc/fstab' and add 'noexec' to the options (4th column) for that filesystem."
  echo "          -> Example: UUID=... /home ext4 defaults,nosuid,noexec 0 2"

  # After providing manual instructions, the status must be 'open' as manual action is needed.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  findings_list=()
  check_results=()
  is_compliant=1 # Assume compliant

  # Use an associative array to store unique mount points for home directories
  declare -A home_mount_points

  # Get local interactive users (UID >= 1000, valid shell) and their home directories
  while IFS=: read -r _ _ _ _ _ home_dir _; do
      if [[ -d "$home_dir" ]]; then
          mount_point=$(df --output=target "$home_dir" | tail -n 1)
          home_mount_points["$mount_point"]=1
      fi
  done < <(getent passwd | awk -F: '$3 >= 1000 && $7 !~ /nologin|false/')
  
  if [[ ${#home_mount_points[@]} -eq 0 ]]; then
      check_results+=("->   Local Users: No local interactive users with home directories found.")
  else
      check_results+=("->   Found the following mount points for user home directories:")
      for mount_p in "${!home_mount_points[@]}"; do
          check_results+=("->     - ${mount_p}")
          if [[ "$mount_p" == "/" ]]; then
              is_compliant=0
              findings_list+=("-> Finding: User home directories are located on the root ('/') filesystem, which cannot have the 'noexec' option.")
              continue
          fi
          
          # Check the fstab entry for the mount point
          fstab_entry=$(grep -E "^\S+\s+${mount_p}\s+" /etc/fstab)
          if [[ -z "$fstab_entry" ]]; then
              is_compliant=0
              findings_list+=("-> Finding: Mount point '${mount_p}' is not defined in /etc/fstab.")
          else
              mount_options=$(echo "$fstab_entry" | awk '{print $4}')
              if ! echo "$mount_options" | grep -q "noexec"; then
                  is_compliant=0
                  findings_list+=("-> Finding: The entry for '${mount_p}' in /etc/fstab is missing the 'noexec' option.")
                  findings_list+=("->   - Entry: ${fstab_entry}")
              fi
          fi
      done
  fi
  
  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
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

