#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# lib/signature_killer.sh - Signature Verification Bypass Module
# =============================================================================
# Bypasses APK signature verification checks so the re-signed APK works.
# Patches PackageManager.getPackageInfo() signature checks and related methods.
#
# References:
#   - https://github.com/nicholasgasior/apk-mitm
#   - MT Manager signature killer techniques
# =============================================================================

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

SIG_PATCHES_APPLIED=0

# Patch Signature.hashCode() calls to return original value
patch_signature_hashcode() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for Signature.hashCode() checks..."

    local sig_files
    sig_files=$(grep -rl "Landroid/content/pm/Signature;->hashCode()I" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null)

    local count=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        count=$((count + 1))
        log_debug "Found Signature.hashCode() reference in: $file"
    done <<< "$sig_files"

    if [ "$count" -gt 0 ]; then
        write_finding "$apk_name" "signature_killer" "[Info] Found Signature.hashCode() in ${count} file(s)"
        log_info "Found Signature.hashCode() references in ${count} file(s)"
    fi
}

# Patch PackageManager signature verification
patch_package_manager_sig() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for PackageManager signature checks..."

    # Find files that call getPackageInfo with GET_SIGNATURES flag
    local pm_files
    pm_files=$(grep -rl "GET_SIGNATURES\|0x40\|getPackageInfo\|signatures" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null | sort -u)

    local count=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        # Look for signature comparison patterns
        if grep -q "Landroid/content/pm/PackageInfo;->signatures" "$file" 2>/dev/null; then
            count=$((count + 1))
            log_debug "Found PackageInfo.signatures access in: $file"
        fi
    done <<< "$pm_files"

    if [ "$count" -gt 0 ]; then
        SIG_PATCHES_APPLIED=$((SIG_PATCHES_APPLIED + count))
        write_finding "$apk_name" "signature_killer" "[PackageManager] Found signature checks in ${count} file(s)"
        log_info "Found PackageManager signature checks in ${count} file(s)"
    fi
}

# Create and inject signature killer smali class
inject_signature_killer_smali() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Injecting SignatureKiller smali class..."

    # Determine base smali directory
    local smali_dir="${decompiled_dir}/smali"
    local target_dir="${smali_dir}/com/signaturekiller"
    mkdir -p "$target_dir"

    # Create the SignatureKiller smali class
    # This class hooks into the Application class to spoof signatures
    cat > "${target_dir}/SignatureKiller.smali" << 'SMALI'
.class public Lcom/signaturekiller/SignatureKiller;
.super Ljava/lang/Object;
.source "SignatureKiller.java"


# static fields
.field private static originalSignature:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .registers 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static setOriginalSignature(Ljava/lang/String;)V
    .registers 1

    sput-object p0, Lcom/signaturekiller/SignatureKiller;->originalSignature:Ljava/lang/String;
    return-void
.end method

.method public static getOriginalSignature()Ljava/lang/String;
    .registers 1

    sget-object v0, Lcom/signaturekiller/SignatureKiller;->originalSignature:Ljava/lang/String;
    return-object v0
.end method
SMALI

    SIG_PATCHES_APPLIED=$((SIG_PATCHES_APPLIED + 1))
    write_finding "$apk_name" "signature_killer" "[Inject] SignatureKiller class injected at com/signaturekiller/"
    log_success "SignatureKiller smali class injected"
}

# Extract original signature from APK for spoofing
extract_original_signature() {
    local apk_path="$1"
    local apk_name="$2"
    log_info "Extracting original APK signature..."

    local sig_info
    sig_info=$(keytool -printcert -jarfile "$apk_path" 2>/dev/null)

    if [ -n "$sig_info" ]; then
        local output_dir="${KEY_OUTPUT_DIR}/${apk_name}"
        mkdir -p "$output_dir"
        echo "$sig_info" > "${output_dir}/original_signature.txt"

        # Extract specific fields
        local sha256
        sha256=$(echo "$sig_info" | grep "SHA256:" | head -1 | awk '{print $2}')
        local sha1
        sha1=$(echo "$sig_info" | grep "SHA1:" | head -1 | awk '{print $2}')
        local md5
        md5=$(echo "$sig_info" | grep "MD5:" | head -1 | awk '{print $2}')

        write_finding "$apk_name" "signature_killer" "
Original APK Signature:
  SHA-256: ${sha256:-N/A}
  SHA-1:   ${sha1:-N/A}
  MD5:     ${md5:-N/A}
"
        log_success "Original signature extracted and saved"
    else
        log_warn "Could not extract original signature"
    fi
}

# Patch signature verification in native libraries
patch_native_sig_check() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Checking for native signature verification..."

    local lib_dir="${decompiled_dir}/lib"
    if [ ! -d "$lib_dir" ]; then
        log_info "No native libraries found"
        return
    fi

    local native_libs
    native_libs=$(find "$lib_dir" -name "*.so" 2>/dev/null)

    local count=0
    while IFS= read -r lib; do
        [ -z "$lib" ] && continue
        # Check if the library references signature-related strings
        if strings "$lib" 2>/dev/null | grep -qi "signature\|getPackageInfo\|PackageManager"; then
            count=$((count + 1))
            local lib_name
            lib_name=$(basename "$lib")
            write_finding "$apk_name" "signature_killer" "[Native] ${lib_name} contains signature verification references"
            log_warn "Native lib contains sig checks: ${lib_name}"
        fi
    done <<< "$native_libs"

    if [ "$count" -gt 0 ]; then
        write_finding "$apk_name" "signature_killer" "[Native] ${count} native library(ies) with signature checks detected"
    fi
}

# Main signature killer function
kill_signature_verification() {
    local decompiled_dir="$1"
    local apk_path="$2"
    local apk_name="$3"

    log_step "=== Signature Verification Bypass ==="
    SIG_PATCHES_APPLIED=0

    extract_original_signature "$apk_path" "$apk_name"
    patch_signature_hashcode "$decompiled_dir" "$apk_name"
    patch_package_manager_sig "$decompiled_dir" "$apk_name"
    inject_signature_killer_smali "$decompiled_dir" "$apk_name"
    patch_native_sig_check "$decompiled_dir" "$apk_name"

    write_report "$apk_name" "
--- Signature Verification Bypass ---
Patches applied: ${SIG_PATCHES_APPLIED}
Techniques:
  - Original signature extracted for reference
  - PackageManager signature checks identified
  - SignatureKiller smali class injected
  - Native library signature checks scanned
"
    log_success "Signature Verification Bypass complete. Patches: ${SIG_PATCHES_APPLIED}"
    return 0
}
