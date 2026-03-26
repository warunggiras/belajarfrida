#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# lib/common.sh - Common utilities and constants
# =============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Logging
log_info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()    { echo -e "${CYAN}[STEP]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_debug()   { [ "${DEBUG:-0}" = "1" ] && echo -e "${MAGENTA}[DBG]${NC} $*"; }

# Paths
TOOLS_DIR="${HOME}/apk-tools"
OUTPUT_BASE="${HOME}/storage/downloads/modify"
KEY_OUTPUT_DIR="${OUTPUT_BASE}/key"
APK_OUTPUT_DIR="${OUTPUT_BASE}/output"
BACKUP_DIR="${OUTPUT_BASE}/backup"
LOG_DIR="${OUTPUT_BASE}/logs"
KEYSTORE_PATH="${TOOLS_DIR}/debug.keystore"
KEYSTORE_PASS="android"
KEY_ALIAS="androiddebugkey"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Ensure output directories exist
ensure_dirs() {
    mkdir -p "$KEY_OUTPUT_DIR" "$APK_OUTPUT_DIR" "$BACKUP_DIR" "$LOG_DIR"
}

# Create a timestamped log file
create_log_file() {
    local apk_name="$1"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local log_file="${LOG_DIR}/${apk_name}_${timestamp}.log"
    echo "$log_file"
}

# Write to both console and log
tee_log() {
    local log_file="$1"
    shift
    echo -e "$*" | tee -a "$log_file"
}

# Check if a command exists
require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Required command not found: ${cmd}"
        log_error "Run setup.sh first to install dependencies."
        return 1
    fi
}

# Validate APK file
validate_apk() {
    local apk="$1"
    if [ ! -f "$apk" ]; then
        log_error "File not found: ${apk}"
        return 1
    fi
    if [[ "$apk" != *.apk ]]; then
        log_error "File does not have .apk extension: ${apk}"
        return 1
    fi
    # Check if it's a valid ZIP (APK is a ZIP archive)
    if ! file "$apk" 2>/dev/null | grep -qi "zip\|android"; then
        log_warn "File may not be a valid APK: ${apk}"
    fi
}

# Get APK package name using aapt
get_package_name() {
    local apk="$1"
    aapt dump badging "$apk" 2>/dev/null | grep "package:" | sed -E "s/.*name='([^']+)'.*/\1/"
}

# Backup original APK
backup_apk() {
    local apk="$1"
    local basename
    basename=$(basename "$apk")
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_path="${BACKUP_DIR}/${basename%.apk}_${timestamp}_original.apk"
    cp "$apk" "$backup_path"
    log_info "Original APK backed up to: ${backup_path}"
    echo "$backup_path"
}

# Write findings to key output directory
# Usage (apk_name form):  write_finding "apk_name" "category" "content line"
# Usage (dir path form):  write_finding "/full/path/dir" "file.txt" "line1" "line2" ...
write_finding() {
    local output_dir="$1"
    local category="$2"
    shift 2
    # If output_dir has no slash, treat it as an apk_name under KEY_OUTPUT_DIR
    if [[ "$output_dir" != */* ]]; then
        output_dir="${KEY_OUTPUT_DIR}/${output_dir}"
    fi
    mkdir -p "$output_dir"
    local file="${output_dir}/${category}"
    # Ensure .txt extension
    [[ "$file" != *.txt ]] && file="${file}.txt"
    for line in "$@"; do
        echo "$line" >> "$file"
    done
    # If no extra args were passed, content is empty (just creates file)
    if [ $# -eq 0 ]; then
        touch "$file"
    fi
}

# Write a report section
write_report() {
    local apk_name="$1"
    local content="$2"
    local output_dir="${KEY_OUTPUT_DIR}/${apk_name}"
    mkdir -p "$output_dir"
    local file="${output_dir}/report.txt"
    echo "$content" >> "$file"
}

# Initialize report
init_report() {
    local apk_name="$1"
    local apk_path="$2"
    local output_dir="${KEY_OUTPUT_DIR}/${apk_name}"
    mkdir -p "$output_dir"
    local file="${output_dir}/report.txt"
    cat > "$file" << EOF
================================================================================
APK Modification Report
================================================================================
APK Name:    ${apk_name}
APK Path:    ${apk_path}
Date:        $(date '+%Y-%m-%d %H:%M:%S')
================================================================================

EOF
}
