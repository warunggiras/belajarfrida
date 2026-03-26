#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# modify_apk.sh - Android APK Modification Toolkit for Termux
# =============================================================================
# All-in-one script for modifying Android APK files. Features:
#   1. SSL Pinning Bypass
#   2. Signature Verification Bypass (SignatureKiller)
#   3. Anti-Frida/Root/Emulator Detection Bypass
#   4. Secret Key & IV Parameter Extraction (Static)
#   5. Encryption/Decryption Method Analysis
#   6. Runtime Hooking (frida-gadget injection for auto key extraction)
#   7. APK Rebuild & Re-signing
#
# Usage:
#   bash modify_apk.sh <path-to-apk> [options]
#
# Options:
#   --ssl-only         Only bypass SSL pinning
#   --sig-only         Only bypass signature verification
#   --anti-frida-only  Only bypass anti-Frida/root detection
#   --extract-only     Only extract secrets (no patching)
#   --hook             Inject frida-gadget for auto runtime hooking
#   --hook-only        Only inject frida-gadget (no static patching)
#   --hook-type <type> Hook type: all, crypto, headers (default: all)
#   --no-rebuild       Skip APK rebuild
#   --output <path>    Custom output path for modified APK
#   --help             Show this help message
#
# Output:
#   Modified APK    -> storage/downloads/modify/output/
#   Extracted keys  -> storage/downloads/modify/key/<apk_name>/
#   Runtime keys    -> /sdcard/Download/modify/key/<package>/ (on device)
#   Reports         -> storage/downloads/modify/key/<apk_name>/report.txt
#   Logs            -> storage/downloads/modify/logs/
#   Backups         -> storage/downloads/modify/backup/
#
# References:
#   - apktool: https://github.com/iBotPeaches/Apktool
#   - jadx:    https://github.com/skylot/jadx
#   - OWASP MSTG: https://mas.owasp.org/MASTG/
#   - Frida:   https://github.com/frida/frida
#   - apk-mitm: https://github.com/nicholasgasior/apk-mitm
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source libraries
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/ssl_pinning.sh"
source "${SCRIPT_DIR}/lib/signature_killer.sh"
source "${SCRIPT_DIR}/lib/anti_frida.sh"
source "${SCRIPT_DIR}/lib/secret_extractor.sh"
source "${SCRIPT_DIR}/lib/apk_builder.sh"
source "${SCRIPT_DIR}/lib/runtime_hooker.sh"

# Default options
DO_SSL=true
DO_SIG=true
DO_ANTI_FRIDA=true
DO_EXTRACT=true
DO_REBUILD=true
DO_HOOK=false
HOOK_TYPE="all"
CUSTOM_OUTPUT=""
APK_PATH=""

show_help() {
    cat << 'HELP'
================================================================================
  APK Modification Toolkit for Termux
================================================================================

Usage:
  bash modify_apk.sh <path-to-apk> [options]

Options:
  --ssl-only         Only bypass SSL pinning
  --sig-only         Only bypass signature verification
  --anti-frida-only  Only bypass anti-Frida/root detection
  --extract-only     Only extract secrets (no patching)
  --hook             Inject frida-gadget for automatic runtime hooking
                     (auto-extracts keys, IVs, headers when app runs)
  --hook-only        Only inject frida-gadget (no static patching)
  --hook-type <type> Hook type: all, crypto, headers (default: all)
  --attach <pkg>     Attach Frida to running app (requires frida-server)
  --no-rebuild       Skip APK rebuild (keep decompiled directory)
  --output <path>    Custom output path for modified APK
  --debug            Enable debug logging
  --help             Show this help message

Features:
  1. SSL Pinning Bypass
     - OkHttp CertificatePinner neutralization
     - X509TrustManager patching
     - HostnameVerifier bypass
     - Network Security Config (trust user certs)
     - WebView SSL error handler patching

  2. Signature Verification Bypass
     - SignatureKiller class injection
     - PackageManager signature check detection
     - Original signature extraction for reference

  3. Anti-Frida/Root/Emulator Detection Bypass
     - Frida port (27042) detection bypass
     - Frida library name obfuscation
     - Root detection method patching
     - Debugger detection bypass
     - Emulator detection bypass
     - App made debuggable

  4. Secret Extraction & Crypto Analysis (Static)
     - AES/DES/RSA key extraction
     - IV parameter detection
     - API key & token extraction
     - Firebase configuration extraction
     - Full encryption/decryption method analysis
     - URL & API endpoint extraction

  5. Runtime Hooking (--hook)
     - Injects frida-gadget into the APK
     - Auto-hooks crypto operations when app launches
     - Captures secret keys, IVs, encryption/decryption at runtime
     - Intercepts HTTP header construction (OkHttp, HttpURLConnection)
     - Captures JWT tokens, auth headers, HMAC signatures
     - Results saved to /sdcard/Download/modify/key/<package>/
       - runtime_keys.txt    (keys, IVs, cipher ops)
       - runtime_headers.txt (headers, tokens, auth)

Output Locations:
  Modified APK  -> ~/storage/downloads/modify/output/
  Secret Keys   -> ~/storage/downloads/modify/key/<apk_name>/
  Reports       -> ~/storage/downloads/modify/key/<apk_name>/report.txt
  Logs          -> ~/storage/downloads/modify/logs/
  Backups       -> ~/storage/downloads/modify/backup/

Prerequisites:
  Run setup.sh first to install all required tools.

================================================================================
HELP
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --help|-h)
                show_help
                exit 0
                ;;
            --ssl-only)
                DO_SIG=false
                DO_ANTI_FRIDA=false
                DO_EXTRACT=false
                DO_HOOK=false
                ;;
            --sig-only)
                DO_SSL=false
                DO_ANTI_FRIDA=false
                DO_EXTRACT=false
                DO_HOOK=false
                ;;
            --anti-frida-only)
                DO_SSL=false
                DO_SIG=false
                DO_EXTRACT=false
                DO_HOOK=false
                ;;
            --extract-only)
                DO_SSL=false
                DO_SIG=false
                DO_ANTI_FRIDA=false
                DO_HOOK=false
                DO_REBUILD=false
                ;;
            --hook)
                DO_HOOK=true
                ;;
            --hook-only)
                DO_SSL=false
                DO_SIG=false
                DO_ANTI_FRIDA=false
                DO_EXTRACT=false
                DO_HOOK=true
                ;;
            --hook-type)
                shift
                HOOK_TYPE="$1"
                ;;
            --no-rebuild)
                DO_REBUILD=false
                ;;
            --output)
                shift
                CUSTOM_OUTPUT="$1"
                ;;
            --debug)
                export DEBUG=1
                ;;
            -*)
                log_error "Unknown option: $1"
                echo "Use --help for usage information."
                exit 1
                ;;
            *)
                if [ -z "$APK_PATH" ]; then
                    APK_PATH="$1"
                else
                    log_error "Multiple APK paths provided. Only one APK at a time."
                    exit 1
                fi
                ;;
        esac
        shift
    done

    if [ -z "$APK_PATH" ]; then
        log_error "No APK file specified."
        echo "Usage: bash modify_apk.sh <path-to-apk> [options]"
        echo "Use --help for more information."
        exit 1
    fi
}

# Decompile APK using apktool
decompile_apk() {
    local apk="$1"
    local output_dir="$2"

    log_step "Decompiling APK with apktool..."
    log_info "Input: ${apk}"
    log_info "Output: ${output_dir}"

    # Remove existing decompiled directory
    rm -rf "$output_dir"

    local decompile_log
    decompile_log=$(mktemp)
    if ! apktool d "$apk" -o "$output_dir" -f > "$decompile_log" 2>&1; then
        log_error "Failed to decompile APK"
        log_error "apktool output: $(cat "$decompile_log")"
        rm -f "$decompile_log"
        return 1
    fi
    rm -f "$decompile_log"

    if [ ! -d "${output_dir}/smali" ]; then
        log_error "Decompilation produced no smali directory"
        return 1
    fi

    local smali_count
    smali_count=$(find "$output_dir" -name "*.smali" 2>/dev/null | wc -l)
    log_success "APK decompiled successfully (${smali_count} smali files)"
    return 0
}

# Optional: Use jadx for Java source analysis (helps with secret extraction)
decompile_java() {
    local apk="$1"
    local output_dir="$2"

    if ! command -v jadx &>/dev/null; then
        log_info "jadx not available, skipping Java decompilation"
        return 0
    fi

    log_step "Decompiling to Java with jadx (for analysis)..."
    jadx -d "$output_dir" "$apk" --no-res --show-bad-code 2>/dev/null || true
    log_info "Java decompilation complete"
}

# Print final summary
print_summary() {
    local apk_name="$1"
    local output_apk="$2"
    local start_time="$3"
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo ""
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${GREEN}  Modification Complete!${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""
    echo -e "  Duration:     ${CYAN}${duration}s${NC}"
    echo -e "  APK Name:     ${CYAN}${apk_name}${NC}"

    if [ -n "$output_apk" ] && [ -f "$output_apk" ]; then
        echo -e "  Modified APK: ${CYAN}${output_apk}${NC}"
    fi

    echo -e "  Keys/Secrets: ${CYAN}${KEY_OUTPUT_DIR}/${apk_name}/${NC}"
    echo -e "  Report:       ${CYAN}${KEY_OUTPUT_DIR}/${apk_name}/report.txt${NC}"

    if [ "$DO_HOOK" = true ]; then
        echo ""
        echo -e "  ${GREEN}Runtime Hooking:${NC}"
        echo -e "    1. Deploy hooks:  ${CYAN}bash ${KEY_OUTPUT_DIR}/${apk_name}/deploy_hooks.sh${NC}"
        echo -e "    2. Install APK:   ${CYAN}adb install -r ${output_apk:-<modified_apk>}${NC}"
        echo -e "    3. Launch app and use it normally"
        echo -e "    4. Pull results:  ${CYAN}adb pull /sdcard/Download/modify/key/${apk_name}/ .${NC}"
    fi
    echo ""

    if [ -d "${KEY_OUTPUT_DIR}/${apk_name}" ]; then
        echo -e "  ${GREEN}Generated files:${NC}"
        find "${KEY_OUTPUT_DIR}/${apk_name}" -type f -exec basename {} \; 2>/dev/null \
            | sort | sed 's/^/    - /'
    fi

    echo ""
    echo -e "${BLUE}=========================================${NC}"
}

main() {
    parse_args "$@"

    local start_time
    start_time=$(date +%s)

    echo -e "${BLUE}=========================================${NC}"
    echo -e "${GREEN}  APK Modification Toolkit${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""

    # Validate environment
    require_cmd java
    require_cmd apktool

    # Ensure output directories exist
    ensure_dirs

    # Validate APK
    validate_apk "$APK_PATH"

    # Determine APK name
    local apk_basename
    apk_basename=$(basename "$APK_PATH" .apk)

    # Initialize report
    init_report "$apk_basename" "$APK_PATH"

    # Backup original
    backup_apk "$APK_PATH"

    # Create working directory
    local work_dir
    work_dir=$(mktemp -d)
    local decompiled_dir="${work_dir}/${apk_basename}"

    # Decompile
    if ! decompile_apk "$APK_PATH" "$decompiled_dir"; then
        log_error "Decompilation failed. Aborting."
        rm -rf "$work_dir"
        exit 1
    fi

    # Run selected modules
    if [ "$DO_SSL" = true ]; then
        bypass_ssl_pinning "$decompiled_dir" "$apk_basename"
    fi

    if [ "$DO_SIG" = true ]; then
        kill_signature_verification "$decompiled_dir" "$APK_PATH" "$apk_basename"
    fi

    if [ "$DO_ANTI_FRIDA" = true ]; then
        bypass_anti_detection "$decompiled_dir" "$apk_basename"
    fi

    if [ "$DO_EXTRACT" = true ]; then
        extract_secrets "$decompiled_dir" "$apk_basename"
    fi

    # Inject frida-gadget for automatic runtime hooking
    if [ "$DO_HOOK" = true ]; then
        local key_dir="${KEY_OUTPUT_DIR}/${apk_basename}"
        mkdir -p "${key_dir}"

        if inject_frida_gadget "$decompiled_dir" "${key_dir}"; then
            generate_hook_instructions "$apk_basename" "${key_dir}"
            write_report "$apk_basename" "
--- Runtime Hooking ---
Frida-gadget injected for automatic runtime hooking.
When the modified APK is installed and launched:
  - Crypto operations are intercepted (keys, IVs, cipher modes)
  - HTTP headers are captured (auth tokens, JWT, HMAC)
  - Results saved to /sdcard/Download/modify/key/${apk_basename}/
  - See runtime_hooks.txt for detailed instructions
"
        else
            write_report "$apk_basename" "
--- Runtime Hooking ---
WARNING: Frida-gadget injection failed.
Use attach mode instead (requires frida-server on device):
  frida -U -l hooks/combined_hooks.js -f <package_name> --no-pause
"
        fi
    fi

    # Rebuild if requested
    local output_apk=""
    if [ "$DO_REBUILD" = true ]; then
        if [ -n "$CUSTOM_OUTPUT" ]; then
            output_apk="$CUSTOM_OUTPUT"
        else
            output_apk="${APK_OUTPUT_DIR}/${apk_basename}_modified.apk"
        fi

        if ! build_and_sign "$decompiled_dir" "$apk_basename" "$output_apk"; then
            log_error "Build failed. Decompiled source preserved at: ${decompiled_dir}"
            # Don't clean up work_dir so user can inspect
            exit 1
        fi
    else
        log_info "Rebuild skipped. Decompiled source at: ${decompiled_dir}"
    fi

    # Finalize report
    write_report "$apk_basename" "
================================================================================
Modification completed at: $(date '+%Y-%m-%d %H:%M:%S')
================================================================================
"

    # Print summary
    print_summary "$apk_basename" "$output_apk" "$start_time"

    # Clean up working directory (if rebuild was done)
    if [ "$DO_REBUILD" = true ]; then
        rm -rf "$work_dir"
    fi

    return 0
}

main "$@"
