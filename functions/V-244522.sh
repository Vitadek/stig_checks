GROUP_ID="V-230230" # Placeholder Group ID for GRUB Superuser
if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."

  # --- Remediation Logic ---
  # First, check if the system is using UEFI. If so, this rule is not applicable.
  if [ -d "/sys/firmware/efi" ]; then
    echo "         -> [N/A] System is using UEFI. This rule is Not Applicable."
    echo "STATUS: not_applicable"
    exit 0
  fi
  
  # This remediation requires manual intervention to choose a unique name and set a password.
  echo "         -> [MANUAL ACTION REQUIRED]"
  echo "         -> To fix this, you must manually edit '/etc/grub.d/01_users' to set a unique superuser name and password."
  echo "         -> 1. Choose a unique name that is not a system user (e.g., 'grubadmin')."
  echo "         -> 2. Generate a GRUB password hash by running: 'sudo grub2-setpassword'"
  echo "         ->    (This will create/update the 'password_pbkdf2 root ...' line in /boot/grub2/user.cfg)."
  echo "         -> 3. Edit '/etc/grub.d/01_users' and add/modify these lines, replacing 'grubadmin' with your chosen name:"
  echo "         ->    set superusers=\"grubadmin\""
  echo "         ->    export superusers"
  echo "         ->    password_pbkdf2 grubadmin \${GRUB2_PASSWORD}"
  echo "         -> 4. Regenerate the grub config file with: 'sudo grub2-mkconfig -o /boot/grub2/grub.cfg'"
  
  # The status is 'open' because manual changes must be made and verified with another scan.
  echo "STATUS: open"
else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  # --- Read-only check logic ---
  # First, check if the system is using UEFI. If so, this rule is not applicable.
  if [ -d "/sys/firmware/efi" ]; then
    echo "         -> [N/A] System is using UEFI. This rule is Not Applicable."
    echo "STATUS: not_applicable"
    exit 0
  fi

  is_compliant=0 # Assume not compliant by default (0 = false)
  grub_config="/boot/grub2/grub.cfg"

  if [[ ! -f "$grub_config" ]]; then
    finding_details="FINDING: GRUB config file '${grub_config}' not found."
  else
    # Extract the superuser name from the config file. It's the string inside the first set of quotes.
    superusername=$(sudo grep -iw "^\s*set\s*superusers" "$grub_config" | cut -d'"' -f2)

    if [[ -z "$superusername" ]]; then
      finding_details="FINDING: The 'superusers' name is not set in '${grub_config}'."
    # Check if the extracted name matches any username in /etc/passwd.
    elif sudo grep -q -w "^${superusername}$" /etc/passwd; then
      finding_details="FINDING: The 'superusers' name ('${superusername}') matches an OS user account."
    else
      is_compliant=1
    fi
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "         -> OK: A unique GRUB superuser name ('${superusername}') is configured."
    echo "STATUS: not_a_finding"
  else
    echo "         -> $finding_details"
    echo "STATUS: open"
  fi
fi
