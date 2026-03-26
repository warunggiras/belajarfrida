#!/usr/bin/env bash
# =============================================================================
# lib/runtime_hooker.sh - Frida Gadget Injection & Runtime Hooking Module
# =============================================================================
# Injects frida-gadget.so into an APK so that when the app is launched,
# it automatically hooks crypto operations, extracts secret keys, IVs,
# encryption/decryption methods, and HTTP header construction.
#
# Two modes:
#   1. Gadget Mode (inject) - Embed frida-gadget into the APK. Hooks run
#      automatically at app launch without needing frida-server.
#   2. Attach Mode (hook)   - Attach to a running process via frida-server
#      (requires frida-server on device and USB/TCP connection).
#
# Output: ~/storage/downloads/modify/key/<package>/
#   - runtime_keys.txt    (secret keys, IVs, cipher operations)
#   - runtime_headers.txt (HTTP headers, auth tokens, JWT)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_DIR="$(cd "${SCRIPT_DIR}/../hooks" && pwd)"

# Frida gadget architecture mapping
declare -A GADGET_ARCH_MAP=(
    ["armeabi-v7a"]="arm"
    ["arm64-v8a"]="arm64"
    ["x86"]="x86"
    ["x86_64"]="x86_64"
)

# =============================================================================
# Detect APK native library architectures
# =============================================================================
detect_apk_architectures() {
    local decompiled_dir="$1"
    local lib_dir="${decompiled_dir}/lib"
    local archs=()

    if [[ -d "${lib_dir}" ]]; then
        for arch_dir in "${lib_dir}"/*/; do
            if [[ -d "${arch_dir}" ]]; then
                local arch
                arch=$(basename "${arch_dir}")
                archs+=("${arch}")
            fi
        done
    fi

    # Default to arm64-v8a and armeabi-v7a if no native libs found
    if [[ ${#archs[@]} -eq 0 ]]; then
        archs=("arm64-v8a" "armeabi-v7a")
        log_info "No native libs found, defaulting to: ${archs[*]}"
    else
        log_info "Detected architectures: ${archs[*]}"
    fi

    echo "${archs[@]}"
}

# =============================================================================
# Download frida-gadget for the target architecture
# =============================================================================
download_frida_gadget() {
    local arch="$1"
    local gadget_dir="${TOOLS_DIR}/frida-gadget"
    local frida_arch="${GADGET_ARCH_MAP[${arch}]:-arm64}"

    mkdir -p "${gadget_dir}"

    local gadget_file="${gadget_dir}/frida-gadget-android-${frida_arch}.so"

    if [[ -f "${gadget_file}" ]]; then
        log_info "Frida gadget already downloaded for ${arch} (${frida_arch})"
        echo "${gadget_file}"
        return 0
    fi

    log_step "Downloading frida-gadget for ${arch} (${frida_arch})..."

    # Get the latest frida release version
    local frida_version
    frida_version=$(python3 -c "import frida; print(frida.__version__)" 2>/dev/null)

    if [[ -z "${frida_version}" ]]; then
        # Fallback: try to get from pip
        frida_version=$(pip show frida 2>/dev/null | grep "^Version:" | awk '{print $2}')
    fi

    if [[ -z "${frida_version}" ]]; then
        frida_version="16.5.9"
        log_info "Using default frida version: ${frida_version}"
    fi

    local download_url="https://github.com/frida/frida/releases/download/${frida_version}/frida-gadget-${frida_version}-android-${frida_arch}.so.xz"

    log_info "Downloading from: ${download_url}"

    if command -v wget &>/dev/null; then
        wget -q -O "${gadget_file}.xz" "${download_url}" 2>/dev/null
    elif command -v curl &>/dev/null; then
        curl -sL -o "${gadget_file}.xz" "${download_url}" 2>/dev/null
    else
        log_error "Neither wget nor curl available"
        return 1
    fi

    if [[ ! -f "${gadget_file}.xz" ]]; then
        log_error "Failed to download frida-gadget for ${frida_arch}"
        return 1
    fi

    # Decompress
    if command -v xz &>/dev/null; then
        xz -d "${gadget_file}.xz"
    elif command -v unxz &>/dev/null; then
        unxz "${gadget_file}.xz"
    else
        log_error "xz/unxz not available to decompress gadget"
        rm -f "${gadget_file}.xz"
        return 1
    fi

    if [[ -f "${gadget_file}" ]]; then
        log_success "Frida gadget downloaded: ${gadget_file}"
        echo "${gadget_file}"
        return 0
    else
        log_error "Failed to decompress frida-gadget"
        return 1
    fi
}

# =============================================================================
# Inject frida-gadget into the decompiled APK
# =============================================================================
inject_frida_gadget() {
    local decompiled_dir="$1"
    local key_output_dir="$2"
    local injected=0

    log_step "Injecting frida-gadget for automatic runtime hooking..."

    # Detect architectures
    local archs
    read -ra archs <<< "$(detect_apk_architectures "${decompiled_dir}")"

    for arch in "${archs[@]}"; do
        local gadget_file
        gadget_file=$(download_frida_gadget "${arch}")

        if [[ -z "${gadget_file}" || ! -f "${gadget_file}" ]]; then
            log_error "Could not obtain frida-gadget for ${arch}, skipping"
            continue
        fi

        local target_lib_dir="${decompiled_dir}/lib/${arch}"
        mkdir -p "${target_lib_dir}"

        # Copy gadget as libfrida-gadget.so
        if cp "${gadget_file}" "${target_lib_dir}/libfrida-gadget.so"; then
            log_success "Injected frida-gadget into lib/${arch}/libfrida-gadget.so"
            injected=1
        else
            log_error "Failed to copy gadget to lib/${arch}/"
        fi
    done

    if [[ ${injected} -eq 0 ]]; then
        log_error "Failed to inject frida-gadget into any architecture"
        write_finding "${key_output_dir}" "runtime_hooks.txt" \
            "[ERROR] Frida gadget injection failed for all architectures"
        return 1
    fi

    # Inject gadget config file for auto-script loading
    inject_gadget_config "${decompiled_dir}"

    # Inject System.loadLibrary call in the main activity smali
    inject_gadget_loader "${decompiled_dir}"

    # Copy the combined hooks script to be pushed to device
    prepare_hooks_script "${decompiled_dir}" "${key_output_dir}"

    write_finding "${key_output_dir}" "runtime_hooks.txt" \
        "=== Frida Gadget Injection ===" \
        "Status: Injected successfully" \
        "Architectures: ${archs[*]}" \
        "Mode: Auto-hook on app launch" \
        "" \
        "When the modified APK is installed and launched:" \
        "  1. Frida gadget loads automatically" \
        "  2. Hooks crypto operations (AES, RSA, DES, HMAC, etc.)" \
        "  3. Captures secret keys, IV parameters, encryption modes" \
        "  4. Intercepts HTTP headers and auth tokens" \
        "  5. Results saved to /sdcard/Download/modify/key/<package>/" \
        "" \
        "Output files on device:" \
        "  - runtime_keys.txt    (secret keys, IVs, cipher operations)" \
        "  - runtime_headers.txt (HTTP headers, auth tokens, JWT)" \
        "" \
        "To pull results from device:" \
        "  adb pull /sdcard/Download/modify/key/ ." \
        ""

    return 0
}

# =============================================================================
# Inject gadget config for auto-script loading
# =============================================================================
inject_gadget_config() {
    local decompiled_dir="$1"

    log_info "Setting up gadget config for auto-script loading..."

    # The gadget config tells frida-gadget to load a JS script on startup
    # The script path must be on the device
    local config_content='{
  "interaction": {
    "type": "script",
    "path": "/data/local/tmp/frida_hooks.js",
    "on_change": "reload"
  }
}'

    # Place config next to each gadget .so
    local lib_dir="${decompiled_dir}/lib"
    if [[ -d "${lib_dir}" ]]; then
        for arch_dir in "${lib_dir}"/*/; do
            if [[ -f "${arch_dir}/libfrida-gadget.so" ]]; then
                # Config must use .config.so extension so it survives APK packaging
                # (APK build tools strip non-.so files from lib/ directories)
                echo "${config_content}" > "${arch_dir}/libfrida-gadget.config.so"
                log_info "Gadget config placed in $(basename "${arch_dir}")"
            fi
        done
    fi
}

# =============================================================================
# Inject System.loadLibrary("frida-gadget") into the main activity
# =============================================================================
inject_gadget_loader() {
    local decompiled_dir="$1"

    log_step "Injecting gadget loader into main activity..."

    # Find the main/launcher activity from AndroidManifest.xml
    local manifest="${decompiled_dir}/AndroidManifest.xml"
    if [[ ! -f "${manifest}" ]]; then
        log_error "AndroidManifest.xml not found"
        return 1
    fi

    # Extract main activity name
    local main_activity
    main_activity=$(grep -B5 'android.intent.action.MAIN' "${manifest}" | \
        grep -oP 'android:name="\K[^"]+' | head -1)

    if [[ -z "${main_activity}" ]]; then
        log_error "Could not determine main activity"
        return 1
    fi

    log_info "Main activity: ${main_activity}"

    # Convert activity class name to smali path
    local activity_path
    activity_path=$(echo "${main_activity}" | sed 's/\./\//g')

    # Handle relative activity names (starting with .)
    if [[ "${activity_path}" == /* ]]; then
        # Need package name prefix
        local pkg_name
        pkg_name=$(grep -oP 'package="\K[^"]+' "${manifest}" | head -1)
        activity_path="${pkg_name//\./\/}${activity_path}"
    fi

    # Find the smali file
    local smali_file=""
    for smali_dir in "${decompiled_dir}"/smali*/; do
        if [[ -f "${smali_dir}${activity_path}.smali" ]]; then
            smali_file="${smali_dir}${activity_path}.smali"
            break
        fi
    done

    if [[ -z "${smali_file}" || ! -f "${smali_file}" ]]; then
        log_error "Smali file not found for ${main_activity}"
        # Try to find Application class instead
        inject_gadget_in_application "${decompiled_dir}"
        return $?
    fi

    log_info "Patching: ${smali_file}"

    # Check if already patched
    if grep -q "frida-gadget" "${smali_file}" 2>/dev/null; then
        log_info "Already patched with gadget loader"
        return 0
    fi

    # Inject System.loadLibrary("frida-gadget") in the static initializer (<clinit>)
    # If no <clinit> exists, inject in onCreate
    if grep -q '\.method static constructor <clinit>()V' "${smali_file}"; then
        # Add loadLibrary call after .locals line in <clinit>
        sed -i '/.method static constructor <clinit>()V/{
            N
            s/\(\.locals [0-9]*\)/\1\n\n    const-string v0, "frida-gadget"\n    invoke-static {v0}, Ljava\/lang\/System;->loadLibrary(Ljava\/lang\/String;)V/
        }' "${smali_file}"
        log_success "Injected gadget loader in <clinit>"
    elif grep -q '\.method.*onCreate' "${smali_file}"; then
        # Add loadLibrary as first operation in onCreate
        sed -i '/\.method.*onCreate/{
            N
            N
            s/\(\.locals [0-9]*\)/\1\n\n    const-string v0, "frida-gadget"\n    invoke-static {v0}, Ljava\/lang\/System;->loadLibrary(Ljava\/lang\/String;)V/
        }' "${smali_file}"
        log_success "Injected gadget loader in onCreate"
    else
        # Create a static initializer block
        # Append before the last .end method or at the end of the file
        cat >> "${smali_file}" << 'SMALI'

.method static constructor <clinit>()V
    .locals 1

    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method
SMALI
        log_success "Created <clinit> with gadget loader"
    fi

    # Ensure extractNativeLibs is true in manifest (required for gadget loading)
    if ! grep -q 'android:extractNativeLibs="true"' "${manifest}"; then
        sed -i 's/<application/<application android:extractNativeLibs="true"/' "${manifest}"
        log_info "Set extractNativeLibs=true in manifest"
    fi

    return 0
}

# =============================================================================
# Fallback: inject gadget loader into Application class
# =============================================================================
inject_gadget_in_application() {
    local decompiled_dir="$1"
    local manifest="${decompiled_dir}/AndroidManifest.xml"

    # Find Application class
    local app_class
    app_class=$(grep -oP 'android:name="\K[^"]+' "${manifest}" | head -1)

    if [[ -z "${app_class}" ]]; then
        log_info "No custom Application class found, trying to find any Activity..."

        # Find any activity smali file
        local any_activity
        any_activity=$(find "${decompiled_dir}"/smali* -name "*.smali" -exec grep -l "Landroid/app/Activity;" {} \; 2>/dev/null | head -1)

        if [[ -z "${any_activity}" ]]; then
            any_activity=$(find "${decompiled_dir}"/smali* -name "*.smali" -exec grep -l "\.method.*onCreate" {} \; 2>/dev/null | head -1)
        fi

        if [[ -n "${any_activity}" ]]; then
            log_info "Injecting gadget in: ${any_activity}"

            if ! grep -q "frida-gadget" "${any_activity}" 2>/dev/null; then
                if grep -q '\.method static constructor <clinit>()V' "${any_activity}"; then
                    sed -i '/.method static constructor <clinit>()V/{
                        N
                        s/\(\.locals [0-9]*\)/\1\n\n    const-string v0, "frida-gadget"\n    invoke-static {v0}, Ljava\/lang\/System;->loadLibrary(Ljava\/lang\/String;)V/
                    }' "${any_activity}"
                else
                    cat >> "${any_activity}" << 'SMALI'

.method static constructor <clinit>()V
    .locals 1

    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method
SMALI
                fi
                log_success "Injected gadget loader in fallback activity"
            fi
            return 0
        fi

        log_error "Could not find any suitable class for gadget injection"
        return 1
    fi

    return 0
}

# =============================================================================
# Prepare hooks script for deployment
# =============================================================================
prepare_hooks_script() {
    local decompiled_dir="$1"
    local key_output_dir="$2"

    log_step "Preparing hooks script for device deployment..."

    # Copy combined hooks to output directory
    if [[ -f "${HOOKS_DIR}/combined_hooks.js" ]]; then
        cp "${HOOKS_DIR}/combined_hooks.js" "${key_output_dir}/frida_hooks.js"
        log_success "Hooks script copied to: ${key_output_dir}/frida_hooks.js"
    else
        log_error "Combined hooks script not found at ${HOOKS_DIR}/combined_hooks.js"
        return 1
    fi

    # Create a deployment script
    cat > "${key_output_dir}/deploy_hooks.sh" << 'DEPLOY'
#!/usr/bin/env bash
# Deploy frida hooks to Android device
# Run this script before launching the modified APK

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_FILE="${SCRIPT_DIR}/frida_hooks.js"

if [[ ! -f "${HOOKS_FILE}" ]]; then
    echo "[!] frida_hooks.js not found in ${SCRIPT_DIR}"
    exit 1
fi

echo "[*] Pushing hooks script to device..."

# Try adb first
if command -v adb &>/dev/null; then
    adb push "${HOOKS_FILE}" /data/local/tmp/frida_hooks.js
    echo "[+] Hooks deployed via adb"
    echo "[*] Now install and launch the modified APK"
    echo "[*] Results will be saved to /sdcard/Download/modify/key/<package>/"
    exit 0
fi

# Termux - copy to shared storage
if [[ -d "/data/data/com.termux" ]]; then
    cp "${HOOKS_FILE}" /data/local/tmp/frida_hooks.js 2>/dev/null || \
    cp "${HOOKS_FILE}" /sdcard/Download/frida_hooks.js
    echo "[+] Hooks deployed"
    echo "[*] If using Termux, you may need to manually copy to /data/local/tmp/"
    echo "    su -c 'cp /sdcard/Download/frida_hooks.js /data/local/tmp/'"
    exit 0
fi

echo "[!] Could not deploy hooks automatically"
echo "[*] Manually copy frida_hooks.js to /data/local/tmp/ on the device"
exit 1
DEPLOY
    chmod +x "${key_output_dir}/deploy_hooks.sh"
    log_success "Deployment script created: ${key_output_dir}/deploy_hooks.sh"

    return 0
}

# =============================================================================
# Run Frida attach mode (alternative to gadget injection)
# =============================================================================
run_frida_attach() {
    local package_name="$1"
    local key_output_dir="$2"
    local hook_type="${3:-all}"  # all, crypto, headers

    log_step "Starting Frida attach mode for: ${package_name}"

    if ! command -v frida &>/dev/null; then
        log_error "Frida not installed. Run setup.sh first."
        return 1
    fi

    local hook_script=""
    case "${hook_type}" in
        crypto)
            hook_script="${HOOKS_DIR}/crypto_hooks.js"
            ;;
        headers)
            hook_script="${HOOKS_DIR}/header_hooks.js"
            ;;
        all|*)
            hook_script="${HOOKS_DIR}/combined_hooks.js"
            ;;
    esac

    if [[ ! -f "${hook_script}" ]]; then
        log_error "Hook script not found: ${hook_script}"
        return 1
    fi

    log_info "Using hook script: ${hook_script}"
    log_info "Output will be saved to device: /sdcard/Download/modify/key/${package_name}/"

    # Check if running via USB or on-device
    if command -v frida &>/dev/null; then
        # Try USB first
        if frida-ps -U 2>/dev/null | head -1 &>/dev/null; then
            log_info "Attaching via USB..."
            frida -U -l "${hook_script}" -f "${package_name}" --no-pause 2>&1 | \
                tee "${key_output_dir}/frida_session.log" &
            local frida_pid=$!
            log_success "Frida session started (PID: ${frida_pid})"
            log_info "Press Ctrl+C to stop the session"
            log_info "Results saved to: /sdcard/Download/modify/key/${package_name}/"
            wait "${frida_pid}" 2>/dev/null
        else
            # Try local (on-device with frida-server)
            log_info "USB not available, trying local mode..."
            frida -l "${hook_script}" -f "${package_name}" --no-pause 2>&1 | \
                tee "${key_output_dir}/frida_session.log" &
            local frida_pid=$!
            log_success "Frida session started (PID: ${frida_pid})"
            wait "${frida_pid}" 2>/dev/null
        fi
    fi

    return 0
}

# =============================================================================
# Generate runtime hooking instructions
# =============================================================================
generate_hook_instructions() {
    local package_name="$1"
    local key_output_dir="$2"

    write_finding "${key_output_dir}" "runtime_hooks.txt" \
        "" \
        "=== Runtime Hooking Instructions ===" \
        "" \
        "Method 1: Gadget Mode (Automatic - Recommended)" \
        "  The modified APK already has frida-gadget injected." \
        "  Steps:" \
        "    1. Deploy hooks script to device:" \
        "       bash ${key_output_dir}/deploy_hooks.sh" \
        "       OR: adb push ${key_output_dir}/frida_hooks.js /data/local/tmp/" \
        "    2. Install the modified APK:" \
        "       adb install -r <modified_apk>" \
        "    3. Launch the app normally" \
        "    4. Use the app - all crypto operations are captured" \
        "    5. Pull results:" \
        "       adb pull /sdcard/Download/modify/key/${package_name}/ ." \
        "" \
        "Method 2: Attach Mode (Manual - Requires frida-server)" \
        "  Steps:" \
        "    1. Start frida-server on device:" \
        "       adb push frida-server /data/local/tmp/" \
        "       adb shell 'chmod 755 /data/local/tmp/frida-server'" \
        "       adb shell '/data/local/tmp/frida-server &'" \
        "    2. Run hooking:" \
        "       frida -U -l hooks/combined_hooks.js -f ${package_name} --no-pause" \
        "    OR for crypto only:" \
        "       frida -U -l hooks/crypto_hooks.js -f ${package_name} --no-pause" \
        "    OR for headers only:" \
        "       frida -U -l hooks/header_hooks.js -f ${package_name} --no-pause" \
        "" \
        "=== What Gets Captured ===" \
        "" \
        "Crypto Operations (runtime_keys.txt):" \
        "  - SecretKeySpec: AES/DES/RSA key values (hex, base64, utf8)" \
        "  - IvParameterSpec: Initialization vectors" \
        "  - GCMParameterSpec: GCM nonces and tag lengths" \
        "  - Cipher.init: Encrypt/decrypt mode, algorithm, key" \
        "  - Cipher.doFinal: Plaintext and ciphertext data" \
        "  - MessageDigest: Hash algorithm and digests" \
        "  - Mac (HMAC): HMAC keys and signatures" \
        "  - PBEKeySpec: Passwords, salts, iterations" \
        "  - KeyGenerator: Generated key values" \
        "  - KeyStore: Key aliases and values" \
        "  - SecretKeyFactory: Derived keys (PBKDF2, etc.)" \
        "" \
        "Header Operations (runtime_headers.txt):" \
        "  - OkHttp3 Request.Builder headers" \
        "  - OkHttp3 Interceptor chain (full request)" \
        "  - HttpURLConnection headers" \
        "  - WebView custom headers" \
        "  - JWT token construction" \
        "  - SharedPreferences (security-related keys)" \
        "  - Authorization header patterns (Bearer, Basic, HMAC)" \
        ""
}
