#!/bin/bash

# =============================================================================
#
# Rule ID:   V-272483
# Filename:  V-272483.sh
# Platform:  RHEL 8+
# Info:      This script verifies the effective SSH client cipher configuration
#            against the FIPS standard on systems using crypto-policies.
#
# Usage:     ./V-272483.sh [--apply-script]
#            --apply-script : Attempts to set the system-wide policy to FIPS.
#                             Requires root privileges.
#
# =============================================================================

# --- Variables ---
REQUIRED_CIPHERS="aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
SCRIPT_STATUS=""

# --- Function to Display Educational Details ---
display_details() {
    local effective_ciphers="$1"
    
    echo ""
    echo "  --- AUDITOR & SYSTEM ADMIN EDUCATIONAL DETAILS ---"
    echo "  This system uses modern System-Wide Cryptographic Policies to manage security."
    echo "  Compliance MUST be verified by checking the live, effective configuration, not by searching"
    echo "  for a specific line in a static configuration file, as older STIGs may require."
    echo ""
    echo "  An active FIPS policy enforces compliant algorithms for SSH and other services automatically."
    echo "  The following commands provide definitive proof of the system's configuration:"
    echo "  --------------------------------------------------------------------------------------------"
    
    # Show the active crypto policy
    echo "  1. Active System-Wide Crypto Policy:"
    echo "     \$ update-crypto-policies --show"
    echo "     -> $(update-crypto-policies --show)"
    echo ""

    # Show the effective ciphers from the command that matters
    echo "  2. Effective SSH Client Ciphers (The Ground Truth):"
    echo "     \$ ssh -G localhost | grep ciphers"
    echo "     -> $(ssh -G localhost | grep ciphers)"
    echo ""

    # Show the backend file for context
    echo "  3. OpenSSH Backend Policy File (For Reference):"
    echo "     \$ grep ciphers /etc/crypto-policies/back-ends/openssh.config"
    echo "     -> $(grep ciphers /etc/crypto-policies/back-ends/openssh.config 2>/dev/null || echo '(No explicit Ciphers line found, which is normal as the policy is enforced by the library)')"
    echo ""
    
    echo "  --- COMPARISON ---"
    echo "  -> Expected FIPS Ciphers: '$REQUIRED_CIPHERS'"
    echo "  -> Actual Effective Ciphers: '$effective_ciphers'"
    echo ""
    
    echo "  --- REFERENCE ---"
    echo "  For more information, see the official Red Hat documentation:"
    echo "  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/using_the_system_wide_cryptographic_policies_security_hardening"
    echo "  --------------------------------------------------------------------------------------------"
}

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
    #
    # ===== REMEDIATION MODE =====
    #
    echo "[FIX]      Applying remediation for Rule V-272483..."

    if [[ $EUID -ne 0 ]]; then
        echo "  -> ERROR: This fix must be run as root." >&2
        SCRIPT_STATUS="error"
        exit 1
    fi

    echo "  -> Setting system-wide crypto policy to FIPS..."
    update-crypto-policies --set FIPS
    
    if [[ $? -eq 0 ]]; then
        echo "  -> SUCCESS: Crypto policy set to FIPS."
    else
        echo "  -> ERROR: Failed to set crypto policy."
        SCRIPT_STATUS="error"
        exit 1
    fi
    
    echo ""
    echo "  [CRITICAL] A system reboot is required for the FIPS policy to take full effect."
    echo ""
    SCRIPT_STATUS="open"

else
    #
    # ===== READ-ONLY CHECK MODE =====
    #
    echo "[CHECK]    Checking effective SSH client cipher compliance for Rule V-272483..."

    effective_ciphers=$(ssh -G localhost | grep -i '^ciphers ' | sed 's/^ciphers //')

    sorted_required_ciphers=$(echo "$REQUIRED_CIPHERS" | tr ',' '\n' | sort | tr '\n' ',')
    sorted_effective_ciphers=$(echo "$effective_ciphers" | tr ',' '\n' | sort | tr '\n' ',')

    if [[ "$sorted_required_ciphers" == "$sorted_effective_ciphers" ]]; then
        echo "  -> OK: System is compliant. The effective SSH client cipher list matches the FIPS requirement."
        SCRIPT_STATUS="not_a_finding"
        display_details "$effective_ciphers"
    else
        echo "  -> FINDING: The effective SSH client cipher list does not match the expected FIPS configuration."
        SCRIPT_STATUS="open"
        display_details "$effective_ciphers"
        echo ""
        echo "  --- RECOMMENDED ACTION ---"
        echo "  Run this script with the '--apply-script' flag as root to set the system policy to FIPS."
    fi
fi

echo "STATUS: ${SCRIPT_STATUS}"
