#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# lib/apk_builder.sh - APK Rebuild and Signing Module
# =============================================================================
# Rebuilds modified APK from decompiled directory and signs it.
#
# References:
#   - https://github.com/iBotPeaches/Apktool
#   - https://developer.android.com/tools/apksigner
# =============================================================================

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Rebuild APK from decompiled directory
rebuild_apk() {
    local decompiled_dir="$1"
    local output_apk="$2"

    log_step "Rebuilding APK..."
    log_info "Source: ${decompiled_dir}"
    log_info "Output: ${output_apk}"

    local build_log
    build_log=$(mktemp)
    if ! apktool b "$decompiled_dir" -o "$output_apk" --use-aapt2 > "$build_log" 2>&1; then
        log_warn "Build with --use-aapt2 failed, trying without..."
        log_debug "Build log: $(cat "$build_log")"
        if ! apktool b "$decompiled_dir" -o "$output_apk" > "$build_log" 2>&1; then
            log_error "Failed to rebuild APK"
            log_error "Build log: $(cat "$build_log")"
            rm -f "$build_log"
            return 1
        fi
    fi
    rm -f "$build_log"

    if [ ! -f "$output_apk" ]; then
        log_error "Output APK not created"
        return 1
    fi

    log_success "APK rebuilt successfully: ${output_apk}"
    return 0
}

# Zipalign the APK
zipalign_apk() {
    local input_apk="$1"
    local output_apk="$2"

    if command -v zipalign &>/dev/null; then
        log_info "Zipaligning APK..."
        zipalign -f 4 "$input_apk" "$output_apk" 2>/dev/null
        if [ -f "$output_apk" ]; then
            log_success "APK zipaligned"
            return 0
        fi
    fi

    # If zipalign not available or failed, just copy
    cp "$input_apk" "$output_apk"
    log_warn "Zipalign not available, skipping"
    return 0
}

# Sign APK with debug keystore
sign_apk() {
    local apk_path="$1"

    log_step "Signing APK..."

    if [ ! -f "$KEYSTORE_PATH" ]; then
        log_warn "Debug keystore not found, generating..."
        keytool -genkeypair \
            -alias "$KEY_ALIAS" \
            -keyalg RSA \
            -keysize 2048 \
            -validity 10000 \
            -keystore "$KEYSTORE_PATH" \
            -storepass "$KEYSTORE_PASS" \
            -keypass "$KEYSTORE_PASS" \
            -dname "CN=Debug,OU=Debug,O=Debug,L=Unknown,ST=Unknown,C=US" \
            2>/dev/null
    fi

    # Try apksigner first (preferred)
    if command -v apksigner &>/dev/null; then
        log_info "Signing with apksigner..."
        apksigner sign \
            --ks "$KEYSTORE_PATH" \
            --ks-pass "pass:${KEYSTORE_PASS}" \
            --ks-key-alias "$KEY_ALIAS" \
            --key-pass "pass:${KEYSTORE_PASS}" \
            "$apk_path" 2>&1

        if apksigner verify "$apk_path" 2>/dev/null; then
            log_success "APK signed and verified with apksigner"
            return 0
        fi
    fi

    # Fallback to jarsigner
    if command -v jarsigner &>/dev/null; then
        log_info "Signing with jarsigner..."
        jarsigner \
            -keystore "$KEYSTORE_PATH" \
            -storepass "$KEYSTORE_PASS" \
            -keypass "$KEYSTORE_PASS" \
            -sigalg SHA256withRSA \
            -digestalg SHA-256 \
            "$apk_path" "$KEY_ALIAS" 2>&1

        if jarsigner -verify "$apk_path" &>/dev/null; then
            log_success "APK signed with jarsigner"
            return 0
        fi
    fi

    log_error "Failed to sign APK - no signing tool available"
    return 1
}

# Full build pipeline: rebuild -> zipalign -> sign
build_and_sign() {
    local decompiled_dir="$1"
    local apk_name="$2"
    local final_output="$3"

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local rebuilt="${tmp_dir}/${apk_name}_rebuilt.apk"
    local aligned="${tmp_dir}/${apk_name}_aligned.apk"

    # Rebuild
    if ! rebuild_apk "$decompiled_dir" "$rebuilt"; then
        rm -rf "$tmp_dir"
        return 1
    fi

    # Zipalign
    zipalign_apk "$rebuilt" "$aligned"

    # Sign
    if ! sign_apk "$aligned"; then
        rm -rf "$tmp_dir"
        return 1
    fi

    # Copy to final destination
    cp "$aligned" "$final_output"
    rm -rf "$tmp_dir"

    local size
    size=$(du -h "$final_output" | cut -f1)
    log_success "Final APK: ${final_output} (${size})"

    write_report "$apk_name" "
--- Build & Sign ---
Output APK: ${final_output}
Size: ${size}
Signed with: debug keystore
Keystore: ${KEYSTORE_PATH}
"
    return 0
}
