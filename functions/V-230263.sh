#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify the OS routinely checks the baseline configuration for unauthorized changes.
GROUP_ID="V-230263"

# --- Pre-flight Checks ---
# This script requires root privileges to check system configuration.
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
  echo "          -> A cron job must be created to run the file integrity tool and email the results."
  echo "          -> 1. Ensure a file integrity tool (e.g., AIDE) and 'mailx' are installed."
  echo "          -> 2. Create a script in a cron directory (e.g., /etc/cron.daily/aide)."
  echo "          -> 3. The script should execute the integrity check and pipe the results to 'mail'."
  echo "          ->    Example for '/etc/cron.daily/aide':"
  echo "          ->    #!/bin/bash"
  echo "          ->    /usr/sbin/aide --check | /bin/mail -s \"\$HOSTNAME - Daily AIDE integrity check\" admin@your_domain.mil"
  echo "          -> 4. Make the script executable: sudo chmod +x /etc/cron.daily/aide"
  
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

  # Check 1: Is a file integrity tool (AIDE) installed?
  if ! rpm -q aide &> /dev/null; then
      is_compliant=0
      findings_list+=("-> Finding: The 'aide' package is not installed. If another file integrity tool is used, this must be documented.")
      check_results+=("->   AIDE Package: Not Installed")
  else
      check_results+=("->   AIDE Package: Installed")
      
      # Check 2: Is there a cron job configured for AIDE?
      cron_job_found=false
      cron_locations=$(grep -rli aide /etc/cron* /etc/crontab /var/spool/cron/ 2>/dev/null)
      
      if [[ -z "$cron_locations" ]]; then
          is_compliant=0
          findings_list+=("-> Finding: No cron job found for AIDE.")
          check_results+=("->   AIDE Cron Job: Not Found")
      else
          cron_job_found=true
          check_results+=("->   AIDE Cron Job: Found in the following location(s):")
          echo "$cron_locations" | while IFS= read -r loc; do
              check_results+=("->     - $loc")
          done
      fi

      # Check 3: If a cron job exists, does it notify?
      if [[ "$cron_job_found" == true ]]; then
          notification_found=false
          # Heuristic: check if the cron file/script pipes aide output to mail or mailx
          if grep -r aide /etc/cron* /etc/crontab /var/spool/cron/ 2>/dev/null | grep -q "|.*mail"; then
              notification_found=true
          fi

          if [[ "$notification_found" == false ]]; then
              is_compliant=0
              findings_list+=("-> Finding: An AIDE cron job was found, but it does not appear to notify personnel (e.g., by piping to 'mail').")
              check_results+=("->   AIDE Notification: Not Detected")
          else
              check_results+=("->   AIDE Notification: Detected (heuristic check passed).")
          fi
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

