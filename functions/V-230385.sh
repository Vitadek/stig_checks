#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify that the umask default for installed shells is "077".
GROUP_ID="V-230385"

# --- Pre-flight Checks ---
# This script requires root privileges to check and modify system configuration files.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Helper Functions ---
function remediate_file() {
    local file_path="$1"
    local desired_setting="umask 077"
    local changes_made_local=false

    if [[ ! -f "$file_path" ]]; then
        return 1
    fi

    # Check for an active umask setting.
    # If one exists but is incorrect, or if none exists, add the correct one.
    if ! grep -q -E "^\s*umask\s+077" "$file_path"; then
        echo "          -> Applying fix: Ensuring 'umask 077' is set in ${file_path}."
        # Add a newline for safety, then the setting.
        echo "" >> "$file_path"
        echo "$desired_setting" >> "$file_path"
        changes_made_local=true
    fi

    if [[ "$changes_made_local" == true ]]; then
        return 0
    else
        return 1
    fi
}

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."
  any_changes_made=false
  files_to_fix=("/etc/bashrc" "/etc/csh.cshrc" "/etc/profile")

  for file in "${files_to_fix[@]}"; do
      remediate_file "$file"
      if [[ $? -eq 0 ]]; then
          any_changes_made=true
      fi
  done
  
  if [[ "$any_changes_made" == true ]]; then
      echo "          -> Remediation logic has been executed."
  else
      echo "          -> No remediation needed. Configuration appears correct."
  fi

  # After applying a fix, the status must be 'open' as a re-scan is needed.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  findings_list=()
  check_results=()
  is_compliant=1 # Assume compliant

  files_to_check=("/etc/bashrc" "/etc/csh.cshrc" "/etc/profile")

  for file in "${files_to_check[@]}"; do
      if [[ ! -f "$file" ]]; then
          check_results+=("->   ${file}: Not found, skipping.")
          continue
      fi

      # Find active (uncommented) umask settings
      active_umasks=$(grep -E "^\s*umask\s+[0-9]+" "$file")

      if [[ -z "$active_umasks" ]]; then
          is_compliant=0
          findings_list+=("-> Finding: No active umask setting found in ${file}.")
          check_results+=("->   ${file}: No active umask found.")
      else
          file_has_finding=false
          check_results+=("->   ${file}:")
          while IFS= read -r line; do
              current_umask=$(echo "$line" | awk '{print $2}')
              check_results+=("->     - Found: '${line}'")
              if [[ "$current_umask" == "000" ]]; then
                  is_compliant=0
                  file_has_finding=true
                  findings_list+=("-> SEVERE Finding (CAT I): umask is set to '${current_umask}' in ${file}.")
              elif [[ "$current_umask" != "077" ]]; then
                  is_compliant=0
                  file_has_finding=true
                  findings_list+=("-> Finding: umask is set to '${current_umask}' instead of '077' in ${file}.")
              fi
          done <<< "$active_umasks"
          if [[ "$file_has_finding" == false ]]; then
              check_results+=("->     - All active umask settings are correct.")
          fi
      fi
  done

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

