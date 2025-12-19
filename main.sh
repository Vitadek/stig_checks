#!/bin/bash

# --- Configuration ---
FUNC_DIR="./functions"
APPLY_FLAG=""
JSON_FILE=""

# --- Argument Parsing ---
for arg in "$@"; do
  case $arg in
    --apply-script)
      APPLY_FLAG="--apply-script"
      shift 
      ;;
    *)
      JSON_FILE="$1"
      shift
      ;;
  esac
done

# --- Input Validation ---
if [[ -z "$JSON_FILE" ]]; then
  echo "Error: JSON file not specified." >&2
  echo "Usage: $0 [--apply-script] <json_file>" >&2
  exit 1
fi

if [[ ! -f "$JSON_FILE" ]]; then
  echo "Error: File not found: $JSON_FILE" >&2
  exit 1
fi

# --- Initialization & Logging Setup ---
# Create a temporary directory for individual script logs.
LOG_DIR=$(mktemp -d)
# Ensure the temporary directory is cleaned up on exit.
trap 'rm -rf -- "$LOG_DIR"' EXIT

# Define the main log directory and create it if it doesn't exist.
MAIN_LOG_DIR="log"
mkdir -p "$MAIN_LOG_DIR"

# Create a main, timestamped log file for the orchestrator script itself.
MAIN_LOG_FILE="${MAIN_LOG_DIR}/orchestrator_$(date +%Y%m%d_%H%M%S).log"
# Redirect all subsequent stdout and stderr to both the console and the main log file.
exec > >(tee -a "$MAIN_LOG_FILE") 2>&1

echo "Orchestrator script started at $(date)"
echo "Main log file created at: $MAIN_LOG_FILE"
echo "Temporary directory for function logs: $LOG_DIR"

# Define the output filename and copy the original to it.
OUTPUT_JSON_FILE="updated_$(basename "$JSON_FILE")"
cp "$JSON_FILE" "$OUTPUT_JSON_FILE"
echo "Results will be written to: $OUTPUT_JSON_FILE"

# --- Main Logic ---
echo "Processing STIG data from $JSON_FILE..."
jq -r '.stigs[].rules[] | select(.status=="open" or .status=="not_reviewed") | .group_id' "$JSON_FILE" | while read -r group_id; do
  
  script_path="${FUNC_DIR}/${group_id}.sh"
  log_path="${LOG_DIR}/${group_id}.log"

  if [[ -x "$script_path" ]]; then
    echo "Executing: $script_path $APPLY_FLAG"
    # Execute the script in the background, redirecting all output to its log file.
    "$script_path" $APPLY_FLAG &> "$log_path" &
  else
    echo "Warning: Script for '$group_id' not found or not executable at $script_path"
    # Create a log for the missing script so we know not to change its status.
    echo "STATUS: error - script not found" > "$log_path"
  fi

done

# --- Concurrency Management ---
echo "Waiting for all checks to complete..."
wait
echo "All tasks completed. Processing results..."
echo "==================================="
echo "Starting JSON update process..."
echo "==================================="

# --- Update JSON Results ---
json_content=$(cat "$OUTPUT_JSON_FILE")

for log_file in "$LOG_DIR"/*.log; do
  group_id=$(basename "$log_file" .log)
  
  finding_details_content=$(cat "$log_file")
  final_status_line=$(grep "STATUS:" "$log_file" | tail -n 1)

  echo "Processing results for $group_id..."
  # If the script was not found, skip any modification for this group_id.
  if [[ "$final_status_line" == *"STATUS: error - script not found"* ]]; then
    echo "  -> Script was not found. No changes will be made to the JSON for this rule."
    continue # Skip to the next log file
  fi

  new_status=""
  if [[ "$final_status_line" == *"STATUS: open"* ]]; then
    new_status="open"
  elif [[ "$final_status_line" == *"STATUS: not_a_finding"* ]]; then
    new_status="not_a_finding"
  elif [[ "$final_status_line" == *"STATUS: not_applicable"* ]]; then
    new_status="not_applicable"
  fi

  echo "  -> Found status line: '$final_status_line'"
  echo "  -> Determined new status: '$new_status'"

  if [[ -n "$new_status" ]]; then
    echo "  -> Preparing to update status to '$new_status' and add finding_details."
    # This command maps over every rule. If it finds a match, it updates
    # the status and finding_details, returning the full JSON object.
    json_content=$(echo "$json_content" | jq \
      --arg gid "$group_id" \
      --arg status "$new_status" \
      --arg details "$finding_details_content" \
      '.stigs[].rules |= map(if .group_id == $gid then . + {status: $status, finding_details: $details} else . end)')
  else
    echo "  -> Preparing to add finding_details only. Status for $group_id remains unchanged."
    # This command maps over every rule. If it finds a match, it adds
    # the finding_details without changing the status.
    json_content=$(echo "$json_content" | jq \
      --arg gid "$group_id" \
      --arg details "$finding_details_content" \
      '.stigs[].rules |= map(if .group_id == $gid then . + {finding_details: $details} else . end)')
  fi
  
  # Check the exit code of the last jq command.
  if [ $? -ne 0 ]; then
    echo "  -> ERROR: The jq command failed for group_id $group_id. Please check the log for details."
  fi
done

# Write the final, modified JSON content back to the output file.
echo "==================================="
echo "Writing final JSON content to $OUTPUT_JSON_FILE"
echo "$json_content" > "$OUTPUT_JSON_FILE"

echo "JSON update complete."


