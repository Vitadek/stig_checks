#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify RHEL 8 is not performing IPv4 packet forwarding.
GROUP_ID="V-250317"

# --- Pre-flight Checks ---
# This script requires root privileges to run sysctl and read system config.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Helper Variables ---
SYSCTL_PARAM="net.ipv4.conf.all.forwarding"
CONFIG_PATHS=(
    "/run/sysctl.d/*.conf"
    "/usr/local/lib/sysctl.d/*.conf"
    "/usr/lib/sysctl.d/*.conf"
    "/lib/sysctl.d/*.conf"
    "/etc/sysctl.conf"
    "/etc/sysctl.d/*.conf"
)

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."
  
  # Create a STIG-specific configuration file to ensure the setting is applied.
  # This file will be processed last, overriding other configurations.
  remediation_file="/etc/sysctl.d/99-V250317-stig.conf"
  echo "          -> Applying fix: Setting '${SYSCTL_PARAM}=0' in '${remediation_file}'."
  echo "${SYSCTL_PARAM}=0" > "${remediation_file}"

  # Reload sysctl settings from all configuration files.
  echo "          -> Applying setting by running 'sysctl --system'."
  sysctl --system >/dev/null 2>&1
  
  echo "          -> Remediation logic has been executed."
  echo "  [WARNING] The fix creates an override file. Review other sysctl configuration files for conflicting entries and remove them if necessary."

  # After applying a fix, the status should be 'open' because it requires a re-scan to confirm compliance.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."
  
  findings_list=()
  is_compliant=1 # Assume compliant

  # 1. Check the runtime value
  current_value=$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null)
  if [[ "$current_value" != "0" ]]; then
      is_compliant=0
      findings_list+=("-> Finding: Runtime value for '${SYSCTL_PARAM}' is '${current_value}', but it should be '0'.")
  fi

  # 2. Check configuration files
  # Suppress "No such file or directory" errors from grep
  all_config_lines=$(grep -rHs -- "${SYSCTL_PARAM}" ${CONFIG_PATHS[@]} 2>/dev/null)
  
  active_lines=$(echo "$all_config_lines" | grep -v "^\s*#")
  commented_lines=$(echo "$all_config_lines" | grep "^\s*#")

  if [[ -n "$commented_lines" ]]; then
      is_compliant=0
      findings_list+=("-> Finding: At least one instance of '${SYSCTL_PARAM}' is commented out. Commented settings should be removed.")
      while IFS= read -r line; do
          findings_list+=("     ->   ${line}")
      done <<< "$commented_lines"
  fi

  if [[ -z "$active_lines" ]]; then
      is_compliant=0
      findings_list+=("-> Finding: The setting '${SYSCTL_PARAM}' is not found in any active configuration files.")
  else
      # Check for non-compliant active settings
      non_compliant_lines=$(echo "$active_lines" | grep -Ev "=\s*0\s*$")
      if [[ -n "$non_compliant_lines" ]]; then
          is_compliant=0
          findings_list+=("-> Finding: One or more configuration files have '${SYSCTL_PARAM}' set to a non-compliant value:")
          while IFS= read -r line; do
              findings_list+=("     ->   ${line}")
          done <<< "$non_compliant_lines"
      fi

      # Check for conflicting active settings
      unique_values=$(echo "$active_lines" | sed -e 's/.*=//' -e 's/ //g' | sort -u)
      if [[ $(echo "$unique_values" | wc -l) -gt 1 ]]; then
          is_compliant=0
          findings_list+=("-> Finding: Conflicting values found for '${SYSCTL_PARAM}': $(echo "$unique_values" | tr '\n' ' ')")
      fi
  fi
  
  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "          -> OK: System is compliant with rule $GROUP_ID."
    echo "          -> Check Results:"
    echo "          ->   Current Runtime Value: ${SYSCTL_PARAM} = ${current_value}"
    echo "          ->   Active Configuration Setting(s):"
    active_compliant_lines=$(grep -rHs -- "^[^#]*${SYSCTL_PARAM}\s*=\s*0" ${CONFIG_PATHS[@]} 2>/dev/null)
    if [[ -n "$active_compliant_lines" ]]; then
        while IFS= read -r line; do
            echo "          ->     ${line}"
        done <<< "$active_compliant_lines"
    else
        echo "          ->     No active configuration file sets '${SYSCTL_PARAM}' to 0, but runtime is compliant."
    fi
    echo "STATUS: not_a_finding"
  else
    echo "          -> FINDING: System is NOT compliant with rule $GROUP_ID."
    for finding in "${findings_list[@]}"; do
        echo "          $finding"
    done
    echo "STATUS: open"
  fi
fi


