GROUP_ID="V-230326"
if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."

  # --- Remediation Logic ---
  # This remediation requires manual intervention to determine the correct owner for unowned files.
  echo "         -> [MANUAL ACTION REQUIRED]"
  echo "         -> Automatic remediation is not performed for this rule."
  echo "         -> 1. Run this script in check mode to identify files without a valid owner."
  echo "         -> 2. For each file listed, investigate why it is unowned."
  echo "         -> 3. Either assign a valid owner with 'sudo chown <user> <file>' or remove the file if it is not needed."
  
  # The status is 'open' because manual changes must be made and verified with another scan.
  echo "STATUS: open"
else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  # --- Read-only check logic ---
  is_compliant=0 # Assume not compliant by default (0 = false)
  
  # Find all files on local filesystems that do not have a valid user.
  # Errors are redirected to /dev/null to hide "Permission denied" messages.
  unowned_files=$(df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null)

  if [[ -z "$unowned_files" ]]; then
    is_compliant=1
  else
    # To avoid excessive output, count the files and show a sample.
    file_count=$(echo "$unowned_files" | wc -l)
    sample_files=$(echo "$unowned_files" | head -n 10)
    finding_details="FINDING: Found ${file_count} file(s) without a valid owner. A sample is listed below:\n${sample_files}"
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "         -> OK: All files and directories on local filesystems have a valid owner."
    echo "STATUS: not_a_finding"
  else
    echo -e "         -> $finding_details"
    echo "STATUS: open"
  fi
fi
