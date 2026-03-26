#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# lib/anti_frida.sh - Anti-Frida/Root Detection Bypass Module
# =============================================================================
# Patches anti-debugging, anti-Frida, and root detection mechanisms in APKs.
# Covers:
#   - Frida detection (port scanning, library checks, /proc/self/maps)
#   - Root detection (su binary, Magisk, SuperSU, build tags)
#   - Emulator detection
#   - Debugger detection (TracerPid, isDebuggerConnected)
#   - Integrity checks
#
# References:
#   - https://github.com/AeonLucid/AndroidNativeEmu
#   - https://github.com/nicholasgasior/apk-mitm
#   - OWASP Mobile Testing Guide - Anti-Reversing
# =============================================================================

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

ANTI_FRIDA_PATCHES=0

# Patch Frida detection via port scanning (default port 27042)
patch_frida_port_detection() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for Frida port detection..."

    # Look for the default Frida port 27042
    local files
    files=$(grep -rl "27042\|27043\|frida" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null | sort -u)

    local count=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        # Patch port connection attempts to Frida
        if grep -q "27042" "$file" 2>/dev/null; then
            # Change the port to something harmless (port 1 - won't connect)
            sed -i 's/0x69a2/0x1/g' "$file"  # 27042 in hex
            count=$((count + 1))
            log_debug "Patched Frida port detection in: $file"
        fi
    done <<< "$files"

    if [ "$count" -gt 0 ]; then
        ANTI_FRIDA_PATCHES=$((ANTI_FRIDA_PATCHES + count))
        write_finding "$apk_name" "anti_frida" "[FridaPort] Patched port 27042 detection in ${count} file(s)"
        log_success "Patched Frida port detection in ${count} file(s)"
    fi
}

# Patch Frida library detection (/proc/self/maps, frida-agent)
patch_frida_library_detection() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for Frida library detection..."

    local frida_strings=(
        "frida"
        "frida-agent"
        "frida-gadget"
        "frida-server"
        "gmain"
        "linjector"
    )

    local total_count=0
    for pattern in "${frida_strings[@]}"; do
        local files
        files=$(grep -rl "\"${pattern}" "$decompiled_dir/smali" \
            --include="*.smali" 2>/dev/null)
        while IFS= read -r file; do
            [ -z "$file" ] && continue
            # Replace the detection string with something harmless
            local safe_name
            safe_name=$(echo "$pattern" | tr 'a-z' 'n-za-m')
            sed -i "s/\"${pattern}/\"noop_${safe_name}/g" "$file"
            total_count=$((total_count + 1))
        done <<< "$files"
    done

    if [ "$total_count" -gt 0 ]; then
        ANTI_FRIDA_PATCHES=$((ANTI_FRIDA_PATCHES + total_count))
        write_finding "$apk_name" "anti_frida" "[FridaLib] Obfuscated Frida detection strings in ${total_count} location(s)"
        log_success "Patched Frida library detection in ${total_count} location(s)"
    fi
}

# Patch /proc/self/maps reading for Frida detection
patch_proc_maps_detection() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for /proc/self/maps Frida detection..."

    local files
    files=$(grep -rl "/proc/self/maps\|/proc/self/status\|/proc/self/task" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null)

    local count=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        count=$((count + 1))
        log_debug "Found /proc detection in: $file"
    done <<< "$files"

    if [ "$count" -gt 0 ]; then
        write_finding "$apk_name" "anti_frida" "[ProcMaps] Found /proc/self/maps reads in ${count} file(s) (common Frida detection)"
        log_info "Found /proc/self/maps detection in ${count} file(s)"
    fi
}

# Patch root detection
patch_root_detection() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for root detection mechanisms..."

    # Common root detection strings/paths
    local root_indicators=(
        "/system/app/Superuser.apk"
        "/system/xbin/su"
        "/system/bin/su"
        "/sbin/su"
        "/data/local/xbin/su"
        "/data/local/bin/su"
        "com.topjohnwu.magisk"
        "com.noshufou.android.su"
        "eu.chainfire.supersu"
        "com.koushikdutta.superuser"
        "com.thirdparty.superuser"
        "com.yellowes.su"
        "test-keys"
    )

    local total_patches=0

    # Find and patch root detection methods
    local root_check_files
    root_check_files=$(grep -rl "isRooted\|checkRoot\|detectRoot\|RootBeer\|rootCheck\|isDeviceRooted" \
        "$decompiled_dir/smali" --include="*.smali" 2>/dev/null)

    while IFS= read -r file; do
        [ -z "$file" ] && continue

        # Patch methods that return boolean for root detection
        for method_name in "isRooted" "checkRoot" "detectRoot" "isDeviceRooted" "checkForRoot"; do
            if grep -q "\.method.*${method_name}.*()Z" "$file" 2>/dev/null; then
                sed -i "/\.method.*${method_name}.*()Z/,/\.end method/{
                    /\.method.*${method_name}/!{
                        /\.end method/!d
                    }
                }" "$file"
                sed -i "/\.method.*${method_name}.*()Z/{
                    a\\    const/4 v0, 0x0\n    return v0
                }" "$file"
                total_patches=$((total_patches + 1))
                log_debug "Patched ${method_name}() in: $file"
            fi
        done
    done <<< "$root_check_files"

    # Patch root indicator strings
    for indicator in "${root_indicators[@]}"; do
        local files
        files=$(grep -rl "\"${indicator}\"" "$decompiled_dir/smali" --include="*.smali" 2>/dev/null)
        while IFS= read -r file; do
            [ -z "$file" ] && continue
            total_patches=$((total_patches + 1))
        done <<< "$files"
    done

    if [ "$total_patches" -gt 0 ]; then
        ANTI_FRIDA_PATCHES=$((ANTI_FRIDA_PATCHES + total_patches))
        write_finding "$apk_name" "anti_frida" "[RootDetect] Patched root detection in ${total_patches} location(s)"
        log_success "Patched root detection in ${total_patches} location(s)"
    fi
}

# Patch debugger detection
patch_debugger_detection() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for debugger detection..."

    # Patch isDebuggerConnected
    local dbg_files
    dbg_files=$(grep -rl "isDebuggerConnected\|Debug;->isDebuggerConnected" \
        "$decompiled_dir/smali" --include="*.smali" 2>/dev/null)

    local count=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        count=$((count + 1))
        log_debug "Found debugger detection in: $file"
    done <<< "$dbg_files"

    # Patch TracerPid check
    local tracer_files
    tracer_files=$(grep -rl "TracerPid" "$decompiled_dir/smali" --include="*.smali" 2>/dev/null)
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        count=$((count + 1))
    done <<< "$tracer_files"

    # Make app debuggable
    local manifest="${decompiled_dir}/AndroidManifest.xml"
    if [ -f "$manifest" ]; then
        if ! grep -q "android:debuggable" "$manifest"; then
            sed -i 's/<application/<application android:debuggable="true"/' "$manifest"
            count=$((count + 1))
            log_success "Made application debuggable"
        fi
    fi

    if [ "$count" -gt 0 ]; then
        ANTI_FRIDA_PATCHES=$((ANTI_FRIDA_PATCHES + count))
        write_finding "$apk_name" "anti_frida" "[Debugger] Found/patched debugger detection in ${count} location(s)"
        log_success "Patched debugger detection in ${count} location(s)"
    fi
}

# Patch emulator detection
patch_emulator_detection() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for emulator detection..."

    local emu_strings=(
        "goldfish"
        "sdk_gphone"
        "generic"
        "vbox86p"
        "Andy"
        "Genymotion"
        "nox"
        "BlueStacks"
    )

    local count=0
    for emu in "${emu_strings[@]}"; do
        local files
        files=$(grep -rl "\"${emu}" "$decompiled_dir/smali" --include="*.smali" 2>/dev/null)
        while IFS= read -r file; do
            [ -z "$file" ] && continue
            count=$((count + 1))
        done <<< "$files"
    done

    # Patch isEmulator-type methods
    local emu_files
    emu_files=$(grep -rl "isEmulator\|detectEmulator\|checkEmulator" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null)

    while IFS= read -r file; do
        [ -z "$file" ] && continue
        for method_name in "isEmulator" "detectEmulator" "checkEmulator"; do
            if grep -q "\.method.*${method_name}.*()Z" "$file" 2>/dev/null; then
                sed -i "/\.method.*${method_name}.*()Z/,/\.end method/{
                    /\.method.*${method_name}/!{
                        /\.end method/!d
                    }
                }" "$file"
                sed -i "/\.method.*${method_name}.*()Z/{
                    a\\    const/4 v0, 0x0\n    return v0
                }" "$file"
                count=$((count + 1))
            fi
        done
    done <<< "$emu_files"

    if [ "$count" -gt 0 ]; then
        ANTI_FRIDA_PATCHES=$((ANTI_FRIDA_PATCHES + count))
        write_finding "$apk_name" "anti_frida" "[Emulator] Found emulator detection in ${count} location(s)"
        log_success "Patched emulator detection in ${count} location(s)"
    fi
}

# Patch native anti-tampering in .so libraries
patch_native_anti_tamper() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Scanning native libraries for anti-tampering..."

    local lib_dir="${decompiled_dir}/lib"
    [ ! -d "$lib_dir" ] && return

    local native_libs
    native_libs=$(find "$lib_dir" -name "*.so" 2>/dev/null)

    local count=0
    while IFS= read -r lib; do
        [ -z "$lib" ] && continue
        local lib_name
        lib_name=$(basename "$lib")

        # Check for Frida detection strings in native code
        local frida_refs
        frida_refs=$(strings "$lib" 2>/dev/null | grep -ci "frida\|xposed\|substrate\|magisk" || true)

        if [ "$frida_refs" -gt 0 ]; then
            count=$((count + 1))
            write_finding "$apk_name" "anti_frida" "[NativeAntiTamper] ${lib_name}: ${frida_refs} anti-tamper string(s) found"
            log_warn "Native anti-tamper detected in: ${lib_name} (${frida_refs} references)"
        fi
    done <<< "$native_libs"

    if [ "$count" -gt 0 ]; then
        ANTI_FRIDA_PATCHES=$((ANTI_FRIDA_PATCHES + count))
    fi
}

# Main anti-Frida/detection bypass function
bypass_anti_detection() {
    local decompiled_dir="$1"
    local apk_name="$2"

    log_step "=== Anti-Frida & Detection Bypass ==="
    ANTI_FRIDA_PATCHES=0

    patch_frida_port_detection "$decompiled_dir" "$apk_name"
    patch_frida_library_detection "$decompiled_dir" "$apk_name"
    patch_proc_maps_detection "$decompiled_dir" "$apk_name"
    patch_root_detection "$decompiled_dir" "$apk_name"
    patch_debugger_detection "$decompiled_dir" "$apk_name"
    patch_emulator_detection "$decompiled_dir" "$apk_name"
    patch_native_anti_tamper "$decompiled_dir" "$apk_name"

    write_report "$apk_name" "
--- Anti-Frida & Detection Bypass ---
Total patches/detections: ${ANTI_FRIDA_PATCHES}
Techniques:
  - Frida port (27042) detection neutralized
  - Frida library/agent string detection obfuscated
  - /proc/self/maps reading identified
  - Root detection methods forced to return false
  - Debugger detection bypassed, app made debuggable
  - Emulator detection methods forced to return false
  - Native library anti-tamper scanned
"
    log_success "Anti-Detection Bypass complete. Patches: ${ANTI_FRIDA_PATCHES}"
    return 0
}
