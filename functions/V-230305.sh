#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify file systems for removable media are mounted with the "nosuid" option.
GROUP_ID="V-230305"

# --- Pre-flight Checks ---
# This script requires root privileges to read /etc/fstab.
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
  echo "          -> File systems associated with removable media must be manually configured."
  echo "          -> 1. Edit the '/etc/fstab' file."
  echo "          -> 2. For each line corresponding to removable media (e.g., usb drives, cd/dvd),"
  echo "          ->    add the 'nosuid' option to the mount options (the 4th column)."
  echo "          ->    Example: UUID=... /mnt/usb vfat noauto,owner,nosuid,nodev 0 0"

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

  # Heuristic for identifying removable media filesystems.
  # Common fs types for removable media. The 'noauto' option is also a strong indicator.
  removable_fs_types="vfat|ntfs|exfat|udf|iso9660|msdos"

  fstab_entries=$(grep -v "^\s*#" /etc/fstab | grep -v "^\s*$")

  if [[ -z "$fstab_entries" ]]; then
      check_results+=("->   /etc/fstab: No active entries found.")
  else
      found_removable=false
      while IFS= read -r line; do
          fs_type=$(echo "$line" | awk '{print $3}')
          mount_options=$(echo "$line" | awk '{print $4}')

          # Check if the line is likely for removable media
          if echo "$fs_type" | grep -qE "$removable_fs_types" || echo "$mount_options" | grep -q "noauto"; then
              found_removable=true
              check_results+=("->   [Removable Media Entry Found]: ${line}")
              if ! echo "$mount_options" | grep -q "nosuid"; then
                  is_compliant=0
                  findings_list+=("-> Finding: Removable media entry does not have the 'nosuid' mount option:")
                  findings_list+=("->   - ${line}")
              fi
          fi
      done <<< "$fstab_entries"

      if [[ "$found_removable" == false ]]; then
          check_results+=("->   /etc/fstab: No entries identified as removable media.")
      fi
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

