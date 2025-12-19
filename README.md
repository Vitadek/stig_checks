# STIG Compliance Orchestrator

This project provides a bash-based framework for automating the scanning and remediation of Security Technical Implementation Guide (STIG) compliance checks.

The system uses a main `orchestrator.sh` script to read a list of security rules from a JSON file. For each rule, it executes a corresponding script that can either check for compliance or apply a fix. Results, including detailed logs, are compiled into an updated JSON file.

## What It Does

The STIG Compliance Orchestrator is designed to automate the security hardening and auditing process. Its key functions are:

1.  **Parallel Execution**: The orchestrator runs all security checks concurrently as background processes, significantly reducing the time required to scan a system with many rules.
2.  **Dual-Mode Operation**: Each rule script can operate in one of two modes:
    *   **Check Mode (Default)**: A read-only scan that inspects system configurations to determine compliance without making any changes.
    *   **Apply Mode (`--apply-script`)**: An active mode that attempts to remediate a security finding by modifying system settings to bring them into compliance.
3.  **Automated JSON Reporting**: The system takes a STIG checklist in JSON format as input. After running the checks, it produces a new JSON file with the `status` and `finding_details` for each rule automatically updated.
4.  **Centralized & Granular Logging**: The orchestrator creates a main timestamped log file for its own operations and also captures a separate, detailed log for each individual rule script. This ensures that you have a complete audit trail of what was checked, what was found, and what was changed.

This framework allows a user to run a compliance scan, review the findings, and then re-run the orchestrator in "apply mode" to automatically fix identified issues. A final verification scan can then confirm the new compliance status.

---

## Usage

### Prerequisites

Before you begin, ensure the following are installed on your system:

*   **`bash`**: The script is designed to run in a standard bash environment.
*   **`jq`**: A command-line JSON processor. The orchestrator relies heavily on `jq` for parsing the input file and generating the output. You can typically install it via your system's package manager (e.g., `sudo apt-get install jq` or `sudo yum install jq`).

### File Structure

Your project should be organized with the following directory structure:

```
.
├── orchestrator.sh         # The main script
├── functions/              # Directory containing individual rule scripts
│   ├── V-000001.sh
│   ├── V-000002.sh
│   └── ...
├── log/                    # Directory where main log files will be stored
└── stig_checklist.json     # Your input JSON file
```

*   `orchestrator.sh` must be an executable file (`chmod +x orchestrator.sh`).
*   Each script inside the `functions/` directory must be named after the `group_id` of the rule it handles (e.g., `V-230221.sh`) and must also be executable (`chmod +x functions/*.sh`).

### Step 1: Running a Compliance Scan (Check Mode)

To check the system's compliance without making any changes, run the orchestrator and provide the path to your JSON file.

```bash
./orchestrator.sh /path/to/your/stig_checklist.json
```

**What Happens:**
*   The orchestrator will parse `stig_checklist.json` and execute the corresponding script from the `functions/` directory for each rule with a status of `"open"` or `"not_reviewed"`.
*   A new file named `updated_stig_checklist.json` will be created in the current directory.
*   This output file will contain the updated results. Rules that are compliant will have their status changed to `"not_a_finding"`. Non-compliant rules will remain `"open"`.
*   The `finding_details` field for each rule will be populated with the full log output from its script.

### Step 2: Applying Fixes (Apply Mode)

After reviewing the results from the check-only scan, you can run the orchestrator in apply mode to automatically remediate the findings.

```bash
./orchestrator.sh --apply-script /path/to/your/stig_checklist.json
```

**What Happens:**
*   The orchestrator runs in the same way, but it passes the `--apply-script` flag to each individual rule script.
*   The rule scripts will execute their remediation logic.
*   After a script applies a fix, it will report its status as `"open"`. This is intentional. A setting that has just been changed requires a fresh, independent scan to verify that the remediation was successful.

### Step 3: Verifying the Fixes

To confirm that the remediation was successful, simply run the compliance scan again in check mode.

```bash
./orchestrator.sh /path/to/your/updated_stig_checklist.json
```

**What Happens:**
*   This final scan will re-evaluate the rules that were just remediated.
*   If the fixes were successful, their status in the new `updated_updated_stig_checklist.json` file will now be `"not_a_finding"`.
