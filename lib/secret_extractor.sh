#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# lib/secret_extractor.sh - Secret Key & Encryption Parameter Extractor
# =============================================================================
# Extracts cryptographic keys, IV parameters, API keys, tokens, and other
# secrets from decompiled APK source code and resources.
# Results are saved to storage/downloads/modify/key/<apk_name>/
#
# References:
#   - OWASP Mobile Security Testing Guide
#   - https://github.com/nicholasgasior/apk-mitm
# =============================================================================

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

SECRETS_FOUND=0

# Extract hardcoded encryption keys from smali
extract_encryption_keys() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for hardcoded encryption keys..."

    local output_file="${KEY_OUTPUT_DIR}/${apk_name}/encryption_keys.txt"
    mkdir -p "$(dirname "$output_file")"
    : > "$output_file"

    # Search for AES/DES/RSA key patterns in smali
    local key_patterns=(
        "AES"
        "DES"
        "DESede"
        "RSA"
        "Blowfish"
        "RC4"
        "ChaCha20"
    )

    echo "=== Encryption Algorithm References ===" >> "$output_file"
    echo "" >> "$output_file"

    for algo in "${key_patterns[@]}"; do
        local files
        files=$(grep -rn "\"${algo}" "$decompiled_dir/smali" --include="*.smali" 2>/dev/null | head -50)
        if [ -n "$files" ]; then
            echo "--- ${algo} ---" >> "$output_file"
            echo "$files" >> "$output_file"
            echo "" >> "$output_file"
            SECRETS_FOUND=$((SECRETS_FOUND + 1))
            log_info "Found ${algo} references"
        fi
    done

    # Search for Cipher.getInstance() calls to identify encryption modes
    echo "=== Cipher Instances (Encryption Modes) ===" >> "$output_file"
    echo "" >> "$output_file"

    local cipher_refs
    cipher_refs=$(grep -rn "Ljavax/crypto/Cipher;->getInstance" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null | head -50)
    if [ -n "$cipher_refs" ]; then
        echo "$cipher_refs" >> "$output_file"
        echo "" >> "$output_file"
        SECRETS_FOUND=$((SECRETS_FOUND + 1))
    fi

    # Extract const-string values near cipher operations
    echo "=== Potential Key/IV String Constants ===" >> "$output_file"
    echo "" >> "$output_file"

    # Look for const-string near SecretKeySpec or IvParameterSpec
    local key_spec_files
    key_spec_files=$(grep -rl "SecretKeySpec\|IvParameterSpec\|PBEKeySpec\|SecretKeyFactory" \
        "$decompiled_dir/smali" --include="*.smali" 2>/dev/null)

    while IFS= read -r file; do
        [ -z "$file" ] && continue
        # Extract const-string values from these files
        local consts
        consts=$(grep "const-string" "$file" 2>/dev/null)
        if [ -n "$consts" ]; then
            echo "File: $(basename "$file")" >> "$output_file"
            echo "$consts" >> "$output_file"
            echo "" >> "$output_file"
            SECRETS_FOUND=$((SECRETS_FOUND + 1))
        fi
    done <<< "$key_spec_files"

    if [ -s "$output_file" ]; then
        write_finding "$apk_name" "secrets" "[EncryptionKeys] Encryption references saved to encryption_keys.txt"
        log_success "Encryption key references extracted"
    fi
}

# Extract IV (Initialization Vector) parameters
extract_iv_parameters() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for IV parameters..."

    local output_file="${KEY_OUTPUT_DIR}/${apk_name}/iv_parameters.txt"
    mkdir -p "$(dirname "$output_file")"
    : > "$output_file"

    echo "=== IV Parameter References ===" >> "$output_file"
    echo "" >> "$output_file"

    # Find IvParameterSpec usage
    local iv_files
    iv_files=$(grep -rn "IvParameterSpec" "$decompiled_dir/smali" --include="*.smali" 2>/dev/null)
    if [ -n "$iv_files" ]; then
        echo "--- IvParameterSpec Usage ---" >> "$output_file"
        echo "$iv_files" >> "$output_file"
        echo "" >> "$output_file"
        SECRETS_FOUND=$((SECRETS_FOUND + 1))
    fi

    # Find GCMParameterSpec (for AES-GCM)
    local gcm_files
    gcm_files=$(grep -rn "GCMParameterSpec" "$decompiled_dir/smali" --include="*.smali" 2>/dev/null)
    if [ -n "$gcm_files" ]; then
        echo "--- GCMParameterSpec Usage ---" >> "$output_file"
        echo "$gcm_files" >> "$output_file"
        echo "" >> "$output_file"
        SECRETS_FOUND=$((SECRETS_FOUND + 1))
    fi

    # Look for hardcoded byte arrays (potential IVs - typically 16 bytes)
    echo "--- Potential Hardcoded IVs (byte arrays) ---" >> "$output_file"
    local byte_arrays
    byte_arrays=$(grep -rn "fill-array-data\|0x10.*new-array" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null | head -30)
    if [ -n "$byte_arrays" ]; then
        echo "$byte_arrays" >> "$output_file"
        echo "" >> "$output_file"
    fi

    if [ -s "$output_file" ]; then
        log_success "IV parameter references extracted"
    fi
}

# Extract API keys, tokens, and secrets from resources
extract_api_keys() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for API keys and tokens..."

    local output_file="${KEY_OUTPUT_DIR}/${apk_name}/api_keys.txt"
    mkdir -p "$(dirname "$output_file")"
    : > "$output_file"

    echo "=== API Keys & Tokens ===" >> "$output_file"
    echo "" >> "$output_file"

    # Search in strings.xml and other resource files
    local res_dir="${decompiled_dir}/res"
    if [ -d "$res_dir" ]; then
        echo "--- From Resource Files ---" >> "$output_file"

        local key_patterns=(
            "api_key"
            "api_secret"
            "apikey"
            "apisecret"
            "secret_key"
            "access_key"
            "access_token"
            "auth_token"
            "client_id"
            "client_secret"
            "app_key"
            "app_secret"
            "firebase"
            "google_maps"
            "google_api"
            "facebook_app"
            "aws_"
        )

        for pattern in "${key_patterns[@]}"; do
            local matches
            matches=$(grep -rni "$pattern" "$res_dir" --include="*.xml" 2>/dev/null | head -10)
            if [ -n "$matches" ]; then
                echo "  [${pattern}]:" >> "$output_file"
                echo "$matches" >> "$output_file"
                echo "" >> "$output_file"
                SECRETS_FOUND=$((SECRETS_FOUND + 1))
            fi
        done
    fi

    # Search in smali code for hardcoded keys
    echo "--- From Smali Code ---" >> "$output_file"

    # Look for base64-encoded strings (potential encoded keys)
    local b64_strings
    b64_strings=$(grep -rn "const-string.*\"[A-Za-z0-9+/]\{32,\}=\"" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null | head -30)
    if [ -n "$b64_strings" ]; then
        echo "  [Base64 Encoded Strings (potential keys)]:" >> "$output_file"
        echo "$b64_strings" >> "$output_file"
        echo "" >> "$output_file"
        SECRETS_FOUND=$((SECRETS_FOUND + 1))
    fi

    # Look for hex strings (potential keys)
    local hex_strings
    hex_strings=$(grep -rn "const-string.*\"[0-9a-fA-F]\{32,\}\"" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null | head -30)
    if [ -n "$hex_strings" ]; then
        echo "  [Hex Strings (potential keys)]:" >> "$output_file"
        echo "$hex_strings" >> "$output_file"
        echo "" >> "$output_file"
        SECRETS_FOUND=$((SECRETS_FOUND + 1))
    fi

    # Search in assets
    local assets_dir="${decompiled_dir}/assets"
    if [ -d "$assets_dir" ]; then
        echo "--- From Assets ---" >> "$output_file"
        local asset_configs
        asset_configs=$(find "$assets_dir" -name "*.json" -o -name "*.xml" -o -name "*.properties" \
            -o -name "*.conf" -o -name "*.cfg" -o -name "*.env" 2>/dev/null)
        while IFS= read -r config_file; do
            [ -z "$config_file" ] && continue
            local keys_in_file
            keys_in_file=$(grep -ni "key\|secret\|token\|password\|api" "$config_file" 2>/dev/null | head -10)
            if [ -n "$keys_in_file" ]; then
                echo "  File: $(basename "$config_file")" >> "$output_file"
                echo "$keys_in_file" >> "$output_file"
                echo "" >> "$output_file"
                SECRETS_FOUND=$((SECRETS_FOUND + 1))
            fi
        done <<< "$asset_configs"
    fi

    if [ -s "$output_file" ]; then
        write_finding "$apk_name" "secrets" "[APIKeys] API keys and tokens saved to api_keys.txt"
        log_success "API key references extracted"
    fi
}

# Extract Firebase/Google configuration
extract_firebase_config() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for Firebase/Google configuration..."

    local output_file="${KEY_OUTPUT_DIR}/${apk_name}/firebase_config.txt"
    mkdir -p "$(dirname "$output_file")"
    : > "$output_file"

    # Check for google-services.json in assets
    local gs_file
    gs_file=$(find "$decompiled_dir" -name "google-services.json" 2>/dev/null | head -1)
    if [ -n "$gs_file" ]; then
        echo "=== google-services.json ===" >> "$output_file"
        cat "$gs_file" >> "$output_file"
        echo "" >> "$output_file"
        SECRETS_FOUND=$((SECRETS_FOUND + 1))
        log_success "Found google-services.json"
    fi

    # Extract Firebase URLs from resources
    local firebase_urls
    firebase_urls=$(grep -rn "firebaseio.com\|firebase.*\.com\|googleapis.com" \
        "$decompiled_dir/res" --include="*.xml" 2>/dev/null)
    if [ -n "$firebase_urls" ]; then
        echo "=== Firebase/Google URLs ===" >> "$output_file"
        echo "$firebase_urls" >> "$output_file"
        echo "" >> "$output_file"
        SECRETS_FOUND=$((SECRETS_FOUND + 1))
    fi

    if [ -s "$output_file" ]; then
        write_finding "$apk_name" "secrets" "[Firebase] Firebase config saved to firebase_config.txt"
    fi
}

# Analyze and document encryption/decryption methods
analyze_crypto_methods() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Analyzing encryption/decryption methods..."

    local output_file="${KEY_OUTPUT_DIR}/${apk_name}/crypto_analysis.txt"
    mkdir -p "$(dirname "$output_file")"
    : > "$output_file"

    echo "=== Cryptographic Method Analysis ===" >> "$output_file"
    echo "Date: $(date '+%Y-%m-%d %H:%M:%S')" >> "$output_file"
    echo "" >> "$output_file"

    # Find all classes that use javax.crypto
    echo "--- Classes Using javax.crypto ---" >> "$output_file"
    local crypto_classes
    crypto_classes=$(grep -rl "Ljavax/crypto/" "$decompiled_dir/smali" --include="*.smali" 2>/dev/null)
    local class_count=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        class_count=$((class_count + 1))
        local rel_path="${file#"$decompiled_dir"/smali/}"
        echo "  - ${rel_path}" >> "$output_file"
    done <<< "$crypto_classes"
    echo "Total classes: ${class_count}" >> "$output_file"
    echo "" >> "$output_file"

    # Identify encryption modes (ECB, CBC, GCM, etc.)
    echo "--- Encryption Modes Detected ---" >> "$output_file"
    local modes=("ECB" "CBC" "GCM" "CTR" "CFB" "OFB" "PKCS5Padding" "PKCS7Padding" "NoPadding")
    for mode in "${modes[@]}"; do
        local mode_count
        mode_count=$(grep -rc "$mode" "$decompiled_dir/smali" --include="*.smali" 2>/dev/null \
            | awk -F: '{s+=$2}END{print s}')
        if [ "${mode_count:-0}" -gt 0 ]; then
            echo "  ${mode}: ${mode_count} reference(s)" >> "$output_file"
        fi
    done
    echo "" >> "$output_file"

    # Find key derivation functions
    echo "--- Key Derivation Functions ---" >> "$output_file"
    local kdf_patterns=("PBKDF2" "SCrypt" "Argon2" "HKDF" "SHA-256" "SHA-512" "MD5" "SHA1")
    for kdf in "${kdf_patterns[@]}"; do
        local kdf_count
        kdf_count=$(grep -rc "$kdf" "$decompiled_dir/smali" --include="*.smali" 2>/dev/null \
            | awk -F: '{s+=$2}END{print s}')
        if [ "${kdf_count:-0}" -gt 0 ]; then
            echo "  ${kdf}: ${kdf_count} reference(s)" >> "$output_file"
            SECRETS_FOUND=$((SECRETS_FOUND + 1))
        fi
    done
    echo "" >> "$output_file"

    # Find MessageDigest usage (hashing)
    echo "--- Hash Function Usage ---" >> "$output_file"
    local hash_refs
    hash_refs=$(grep -rn "MessageDigest\|DigestUtils" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null | head -20)
    if [ -n "$hash_refs" ]; then
        echo "$hash_refs" >> "$output_file"
    fi
    echo "" >> "$output_file"

    # Find KeyStore usage
    echo "--- KeyStore Usage ---" >> "$output_file"
    local ks_refs
    ks_refs=$(grep -rn "Ljava/security/KeyStore\|AndroidKeyStore" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null | head -20)
    if [ -n "$ks_refs" ]; then
        echo "$ks_refs" >> "$output_file"
        SECRETS_FOUND=$((SECRETS_FOUND + 1))
    fi
    echo "" >> "$output_file"

    # Document encrypt/decrypt method locations
    echo "--- Encrypt/Decrypt Method Locations ---" >> "$output_file"
    local enc_methods
    enc_methods=$(grep -rn "encrypt\|decrypt\|doFinal\|cipher" "$decompiled_dir/smali" \
        --include="*.smali" -i 2>/dev/null | grep "\.method\|invoke" | head -40)
    if [ -n "$enc_methods" ]; then
        echo "$enc_methods" >> "$output_file"
        SECRETS_FOUND=$((SECRETS_FOUND + 1))
    fi
    echo "" >> "$output_file"

    if [ -s "$output_file" ]; then
        write_finding "$apk_name" "secrets" "[CryptoAnalysis] Full crypto analysis saved to crypto_analysis.txt"
        log_success "Cryptographic analysis complete"
    fi
}

# Extract URLs and endpoints
extract_urls() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Extracting URLs and API endpoints..."

    local output_file="${KEY_OUTPUT_DIR}/${apk_name}/urls_endpoints.txt"
    mkdir -p "$(dirname "$output_file")"
    : > "$output_file"

    echo "=== URLs & API Endpoints ===" >> "$output_file"
    echo "" >> "$output_file"

    # Extract HTTP/HTTPS URLs from smali
    echo "--- HTTP/HTTPS URLs ---" >> "$output_file"
    local urls
    urls=$(grep -roP "https?://[^\"\s<>']+" "$decompiled_dir/smali" --include="*.smali" 2>/dev/null \
        | sort -u | head -100)
    if [ -n "$urls" ]; then
        echo "$urls" >> "$output_file"
        SECRETS_FOUND=$((SECRETS_FOUND + 1))
    fi
    echo "" >> "$output_file"

    # Extract from resources too
    echo "--- URLs from Resources ---" >> "$output_file"
    local res_urls
    res_urls=$(grep -roP "https?://[^\"\s<>']+" "$decompiled_dir/res" --include="*.xml" 2>/dev/null \
        | sort -u | head -50)
    if [ -n "$res_urls" ]; then
        echo "$res_urls" >> "$output_file"
    fi
    echo "" >> "$output_file"

    if [ -s "$output_file" ]; then
        write_finding "$apk_name" "secrets" "[URLs] URLs and endpoints saved to urls_endpoints.txt"
        log_success "URLs and endpoints extracted"
    fi
}

# Main secret extraction function
extract_secrets() {
    local decompiled_dir="$1"
    local apk_name="$2"

    log_step "=== Secret Key & Parameter Extraction ==="
    SECRETS_FOUND=0

    extract_encryption_keys "$decompiled_dir" "$apk_name"
    extract_iv_parameters "$decompiled_dir" "$apk_name"
    extract_api_keys "$decompiled_dir" "$apk_name"
    extract_firebase_config "$decompiled_dir" "$apk_name"
    analyze_crypto_methods "$decompiled_dir" "$apk_name"
    extract_urls "$decompiled_dir" "$apk_name"

    write_report "$apk_name" "
--- Secret Key & Parameter Extraction ---
Total findings: ${SECRETS_FOUND}
Output directory: ${KEY_OUTPUT_DIR}/${apk_name}/
Files generated:
  - encryption_keys.txt    : Encryption algorithm references and key constants
  - iv_parameters.txt      : IV/nonce parameter references
  - api_keys.txt           : API keys, tokens, and secrets
  - firebase_config.txt    : Firebase/Google configuration
  - crypto_analysis.txt    : Full cryptographic method analysis
  - urls_endpoints.txt     : URLs and API endpoints
"
    log_success "Secret extraction complete. Findings: ${SECRETS_FOUND}"
    log_info "Results saved to: ${KEY_OUTPUT_DIR}/${apk_name}/"
    return 0
}
