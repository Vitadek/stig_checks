#!/bin/bash

# --- Configuration ---
# STIG Group ID for the rule:
# Verify that the operating system is configured to allow sending email notifications.
GROUP_ID="V-256974"

# --- Pre-flight Checks ---
# This script requires root privileges to check for and install packages.
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  # Standardized exit status
  echo "STATUS: error"
  exit 1
fi

# --- Helper Variables ---
# Define the required package name.
PACKAGE_NAME="mailx"

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
  #
  # ===== APPLY MODE =====
  #
  echo "[APPLY]   Running remediation for rule $GROUP_ID..."

  # --- Remediation Logic ---
  # Ensures the mailx package is installed.
  if ! rpm -q "$PACKAGE_NAME" &>/dev/null; then
    echo "          -> Applying fix: Installing package '${PACKAGE_NAME}'."
    # Use -y flag to automatically answer yes to prompts.
    yum install -y "$PACKAGE_NAME"
    echo "          -> Remediation logic has been executed."
  else
    echo "          -> No remediation needed. Package '${PACKAGE_NAME}' is already installed."
  fi
  
  echo "  [WARNING] Review system changes to ensure correctness."

  # After applying a fix, the status should be 'open' because it requires a re-scan to confirm compliance.
  echo "STATUS: open"

else
  #
  # ===== READ-ONLY CHECK MODE =====
  #
  echo "[CHECK]   Checking compliance for rule $GROUP_ID..."

  # --- Read-only check logic ---
  # The goal is to determine if the mailx package is installed.
  is_compliant=0 # Assume not compliant by default

  # Use rpm -q for a clean check. Redirect stdout and stderr to /dev/null.
  if rpm -q "$PACKAGE_NAME" &>/dev/null; then
    is_compliant=1 # Set to true if compliant
  fi

  # Report the final status based on the check.
  if [[ $is_compliant -eq 1 ]]; then
    echo "          -> OK: System is compliant with rule $GROUP_ID."
    echo "          -> Package '${PACKAGE_NAME}' is installed."
    echo "STATUS: not_a_finding"
  else
    echo "          -> FINDING: System is NOT compliant with rule $GROUP_ID."
    echo "          -> Package '${PACKAGE_NAME}' is not installed."
    echo "STATUS: open"
  fi
fi

