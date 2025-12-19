#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify that local initialization files do not execute world-writable programs.
GROUP_ID="V-230309"

# --- Pre-flight Checks ---
# This script requires root privileges to scan the filesystem and read user files.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Helper Functions ---
function get_local_interactive_users_homes() {
    # Get home directories of users with UID >= 1000 and a valid login shell
    getent passwd | awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $6}'
}

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."
  echo "          -> MANUAL REMEDIATION REQUIRED:"
  echo "          -> World-writable files executed by initialization files must be secured."
  echo "          -> For each finding, either remove the execution from the initialization file"
  echo "          -> or fix the file's permissions, for example:"
  echo "          ->   sudo chmod 0755 <file_path>"
  
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

  # Step 1: Find all world-writable files on local filesystems
  world_writable_files=$(df --local -P | awk 'NR>1 {print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null)
  
  if [[ -z "$world_writable_files" ]]; then
      check_results+=("->   World-writable files: None found on local filesystems.")
  else
      check_results+=("->   World-writable files: Found. Checking usage in user init files...")
      
      # Step 2: Check if any of these files are in user initialization files
      user_homes=$(get_local_interactive_users_homes)
      
      found_insecure_ref=false
      for ww_file in $world_writable_files; do
          for home_dir in $user_homes; do
              if [[ -d "$home_dir" ]]; then
                  # Grep for the exact file path in the user's dotfiles
                  references=$(grep -Fw -- "$ww_file" "$home_dir"/.[a-zA-Z]* 2>/dev/null)
                  if [[ -n "$references" ]]; then
                      is_compliant=0
                      found_insecure_ref=true
                      findings_list+=("-> Finding: World-writable file '${ww_file}' is referenced in the following location(s):")
                      echo "$references" | while IFS= read -r line; do
                          findings_list+=("->   - ${line}")
                      done
                  fi
              fi
          done
      done
      
      if [[ "$found_insecure_ref" == true ]]; then
        check_results+=("->   Initialization File Check: Found references to world-writable files.")
      else
        check_results+=("->   Initialization File Check: No references to found world-writable files.")
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

