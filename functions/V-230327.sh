#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify all local files and directories on RHEL 8 have a valid group.
GROUP_ID="V-230327"

# --- Pre-flight Checks ---
# This script requires root privileges to scan the entire filesystem.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Main Logic ---

# Get a list of files with no group owner
files_without_group=$(df --local -P | awk 'NR>1 {print $6}' | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null)

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."
  echo "          -> MANUAL REMEDIATION REQUIRED:"
  echo "          -> Files without a valid group owner must be reviewed and either removed"
  echo "          -> or assigned a valid group using the 'chgrp' command."
  echo "          -> Example: sudo chgrp <group_name> <file_path>"
  
  if [[ -n "$files_without_group" ]]; then
      echo "          -> The following files were found without a valid group:"
      echo "$files_without_group" | while IFS= read -r file; do
          echo "          ->   - $file"
      done
  else
      echo "          -> No files found without a valid group."
  fi

  # After providing manual instructions, the status must be 'open' as manual action is needed.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  # The check logic is performed before the if/else block.
  # Now we just report on the findings.

  if [[ -z "$files_without_group" ]]; then
    echo "          -> OK: System is compliant with rule $GROUP_ID."
    echo "          -> Check Results:"
    echo "          ->   No files or directories found without a valid group."
    echo "STATUS: not_a_finding"
  else
    echo "          -> FINDING: System is NOT compliant with rule $GROUP_ID."
    echo "          -> Check Results:"
    echo "          -> Finding: The following files and directories do not have a valid group owner:"
    echo "$files_without_group" | while IFS= read -r file; do
        echo "          ->   - $file"
    done
    echo "STATUS: open"
  fi
fi

