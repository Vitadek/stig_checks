#!/bin/bash

# =============================================================================
#
# Rule ID:   V-272482
# Filename:  V-272482.sh
# Platform:  RHEL 8+
# Info:      This script verifies the effective SSH client MAC configuration
#            against the FIPS standard on systems using crypto-policies.
#
# Usage:     ./V-272482.sh [--apply-script]
#            --apply-script : Attempts to set the system-wide policy to FIPS.
#                             Requires root privileges.
#
# =============================================================================

# --- Variables ---
REQUIRED_MACS="hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
SCRIPT_STATUS=""

# --- Function to Display Educational Details ---
display_details() {
    local effective_macs="$1"
    
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

    # Show the effective MACs from the command that matters
    echo "  2. Effective SSH Client MACs (The Ground Truth):"
    echo "     \$ ssh -G localhost | grep -i '^macs '"
    echo "     -> $(ssh -G localhost | grep -i '^macs ')"
    echo ""

    # Show the backend file for context
    echo "  3. OpenSSH Backend Policy File (For Reference):"
    echo "     \$ grep -i macs /etc/crypto-policies/back-ends/openssh.config"
    echo "     -> $(grep -i macs /etc/crypto-policies/back-ends/openssh.config 2>/dev/null || echo '(No explicit MACs line found, which is normal as the policy is enforced by the library)')"
    echo ""
    
    echo "  --- COMPARISON ---"
    echo "  -> Expected FIPS MACs: '$REQUIRED_MACS'"
    echo "  -> Actual Effective MACs: '$effective_macs'"
    echo ""
    
    echo "  --- REFERENCE ---"
    echo "  For more information, see the official Red Hat documentation:"
    echo "  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/using-the-system_wide_cryptographic-policies_security_hardening"
    echo "  NIST Specification:"
    echo "  https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4985.pdf"
    echo "  (Reference: Section 4.3 Approved Services)"
    echo "  --------------------------------------------------------------------------------------------"
}

# --- Main Logic ---

if [[ "$1" == "--apply-script" ]]; then
    #
    # ===== REMEDIATION MODE =====
    #
    echo "[FIX]      Applying remediation for Rule V-272482..."

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
    echo "[CHECK]    Checking effective SSH client MAC compliance for Rule V-272482..."

    effective_macs=$(ssh -G localhost | grep -i '^macs ' | sed 's/^macs //')

    sorted_required_macs=$(echo "$REQUIRED_MACS" | tr ',' '\n' | sort | tr '\n' ',')
    sorted_effective_macs=$(echo "$effective_macs" | tr ',' '\n' | sort | tr '\n' ',')

    if [[ "$sorted_required_macs" == "$sorted_effective_macs" ]]; then
        echo "  -> OK: System is compliant. The effective SSH client MAC list matches the FIPS requirement."
        SCRIPT_STATUS="not_a_finding"
        display_details "$effective_macs"
    else
        echo "  -> FINDING: The effective SSH client MAC list does not match the expected FIPS configuration."
        SCRIPT_STATUS="open"
        display_details "$effective_macs"
        echo ""
        echo "  --- RECOMMENDED ACTION ---"
        echo "  Run this script with the '--apply-script' flag as root to set the system policy to FIPS."
    fi
fi

echo "STATUS: ${SCRIPT_STATUS}"
