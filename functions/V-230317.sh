#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify local interactive user initialization files do not have insecure PATH statements.
GROUP_ID="V-230317"

# --- Pre-flight Checks ---
# This script requires root privileges to read user home directories.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Helper Functions ---
function get_local_interactive_users() {
    # Get users with UID >= 1000 and a valid login shell
    getent passwd | awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1 ":" $6}'
}

# --- Main Logic ---

# Gather all PATH statements from local user init files
path_findings=$(
    get_local_interactive_users | while IFS=: read -r user home_dir; do
        if [[ -d "$home_dir" ]]; then
            # Search for lines defining or exporting PATH in dotfiles
            grep -E '^\s*(export\s+)?PATH=' "$home_dir"/.[a-zA-Z]* 2>/dev/null | sed "s|^|${home_dir}: |"
        fi
    done
)

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."
  echo "          -> MANUAL REMEDIATION REQUIRED:"
  echo "          -> User initialization files must be manually reviewed to ensure PATH statements"
  echo "          -> do not reference directories outside of the user's home directory unless"
  echo "          -> documented as an operational requirement with the ISSO."
  
  if [[ -n "$path_findings" ]]; then
      echo "          -> The following PATH statements were found and require review:"
      echo "$path_findings" | while IFS= read -r line; do
          file=$(echo "$line" | cut -d':' -f1,2)
          content=$(echo "$line" | cut -d':' -f3-)
          echo "          ->   - File: ${file}"
          echo "          ->     Content: ${content}"
      done
  else
      echo "          -> No PATH statements found in local interactive user initialization files."
  fi

  # After providing manual instructions, the status must be 'open' as manual action is needed.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  # The check logic is performed before the if/else block.
  # This check always requires manual review, so it is always a finding.

  if [[ -z "$path_findings" ]]; then
    echo "          -> OK: System is compliant with rule $GROUP_ID."
    echo "          -> Check Results:"
    echo "          ->   No PATH statements found in local interactive user initialization files."
    echo "STATUS: not_a_finding"
  else
    echo "          -> FINDING: System is NOT compliant with rule $GROUP_ID."
    echo "          -> Check Results:"
    echo "          -> Finding: The following PATH statements must be manually reviewed to ensure they"
    echo "          ->          do not reference unauthorized directories:"
    echo "$path_findings" | while IFS= read -r line; do
        file=$(echo "$line" | cut -d':' -f1,2)
        content=$(echo "$line" | cut -d':' -f3-)
        echo "          ->   - File: ${file}"
        echo "          ->     Content: ${content}"
    done
    echo "STATUS: not_reviewed"
  fi
fi

