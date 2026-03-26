#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# lib/ssl_pinning.sh - SSL Pinning Bypass Module
# =============================================================================
# Patches smali code to bypass SSL certificate pinning in Android apps.
# Covers common pinning implementations:
#   - OkHttp CertificatePinner
#   - TrustManager / X509TrustManager
#   - Network Security Config
#   - WebViewClient SSL errors
#   - Apache HTTP client
#
# References:
#   - https://github.com/nicholasgasior/apk-mitm
#   - https://github.com/frida/frida
#   - https://github.com/httptoolkit/frida-interception-and-unpinning
# =============================================================================

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Count of patches applied
SSL_PATCHES_APPLIED=0

# Patch OkHttp3 CertificatePinner
patch_okhttp_pinner() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for OkHttp CertificatePinner..."

    local pinner_files
    pinner_files=$(find "$decompiled_dir" -name "CertificatePinner.smali" -o -name "CertificatePinner\$*.smali" 2>/dev/null)

    if [ -z "$pinner_files" ]; then
        # Search by class reference pattern in obfuscated code
        pinner_files=$(grep -rl "certificatePinner\|CertificatePinner\|\.check(" "$decompiled_dir/smali" \
            --include="*.smali" 2>/dev/null | head -20)
    fi

    local count=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        if grep -q "\.method.*check(" "$file" 2>/dev/null; then
            # Replace check method body with empty return
            sed -i '/\.method.*check(/,/\.end method/{
                /\.method.*check(/!{
                    /\.end method/!d
                }
            }' "$file"
            # Insert return-void after method declaration
            sed -i '/\.method.*check(/{
                a\    return-void
            }' "$file"
            count=$((count + 1))
            log_debug "Patched CertificatePinner.check() in: $file"
        fi
    done <<< "$pinner_files"

    if [ "$count" -gt 0 ]; then
        SSL_PATCHES_APPLIED=$((SSL_PATCHES_APPLIED + count))
        write_finding "$apk_name" "ssl_pinning" "[OkHttp] Patched CertificatePinner.check() in ${count} file(s)"
        log_success "Patched OkHttp CertificatePinner in ${count} file(s)"
    fi
}

# Patch TrustManager implementations
patch_trustmanager() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for TrustManager implementations..."

    # Find classes implementing X509TrustManager
    local tm_files
    tm_files=$(grep -rl "Ljavax/net/ssl/X509TrustManager;" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null)

    local count=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue

        # Patch checkServerTrusted to return void (accept all certs)
        if grep -q "checkServerTrusted" "$file" 2>/dev/null; then
            sed -i '/\.method.*checkServerTrusted/,/\.end method/{
                /\.method.*checkServerTrusted/!{
                    /\.end method/!d
                }
            }' "$file"
            sed -i '/\.method.*checkServerTrusted/{
                a\    return-void
            }' "$file"
            count=$((count + 1))
            log_debug "Patched checkServerTrusted in: $file"
        fi

        # Patch checkClientTrusted similarly
        if grep -q "checkClientTrusted" "$file" 2>/dev/null; then
            sed -i '/\.method.*checkClientTrusted/,/\.end method/{
                /\.method.*checkClientTrusted/!{
                    /\.end method/!d
                }
            }' "$file"
            sed -i '/\.method.*checkClientTrusted/{
                a\    return-void
            }' "$file"
        fi
    done <<< "$tm_files"

    if [ "$count" -gt 0 ]; then
        SSL_PATCHES_APPLIED=$((SSL_PATCHES_APPLIED + count))
        write_finding "$apk_name" "ssl_pinning" "[TrustManager] Patched checkServerTrusted in ${count} file(s)"
        log_success "Patched TrustManager in ${count} file(s)"
    fi
}

# Patch HostnameVerifier
patch_hostname_verifier() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for HostnameVerifier implementations..."

    local hv_files
    hv_files=$(grep -rl "Ljavax/net/ssl/HostnameVerifier;" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null)

    local count=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        if grep -q "\.method.*verify(" "$file" 2>/dev/null; then
            # Make verify() return true (const/4 v0, 0x1 + return v0)
            sed -i '/\.method.*verify(Ljava\/lang\/String;Ljavax\/net\/ssl\/SSLSession;)Z/,/\.end method/{
                /\.method.*verify/!{
                    /\.end method/!d
                }
            }' "$file"
            sed -i '/\.method.*verify(Ljava\/lang\/String;Ljavax\/net\/ssl\/SSLSession;)Z/{
                a\    const/4 v0, 0x1\n    return v0
            }' "$file"
            count=$((count + 1))
            log_debug "Patched HostnameVerifier.verify() in: $file"
        fi
    done <<< "$hv_files"

    if [ "$count" -gt 0 ]; then
        SSL_PATCHES_APPLIED=$((SSL_PATCHES_APPLIED + count))
        write_finding "$apk_name" "ssl_pinning" "[HostnameVerifier] Patched verify() in ${count} file(s)"
        log_success "Patched HostnameVerifier in ${count} file(s)"
    fi
}

# Add/modify Network Security Config to trust user certificates
patch_network_security_config() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Patching Network Security Config..."

    local res_xml_dir="${decompiled_dir}/res/xml"
    mkdir -p "$res_xml_dir"

    # Create a permissive network_security_config.xml
    cat > "${res_xml_dir}/network_security_config.xml" << 'XML'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
XML

    # Update AndroidManifest.xml to reference the config
    local manifest="${decompiled_dir}/AndroidManifest.xml"
    if [ -f "$manifest" ]; then
        if ! grep -q "networkSecurityConfig" "$manifest"; then
            # Only add to the first <application tag
            sed -i '0,/<application/{s/<application/<application android:networkSecurityConfig="@xml\/network_security_config"/}' "$manifest"
            log_success "Added networkSecurityConfig to AndroidManifest.xml"
        else
            log_info "networkSecurityConfig already present in manifest"
        fi

        # Also ensure usesCleartextTraffic is true
        if ! grep -q "usesCleartextTraffic" "$manifest"; then
            sed -i '0,/<application/{s/<application/<application android:usesCleartextTraffic="true"/}' "$manifest"
        fi
    fi

    SSL_PATCHES_APPLIED=$((SSL_PATCHES_APPLIED + 1))
    write_finding "$apk_name" "ssl_pinning" "[NetworkSecurityConfig] Added permissive config trusting user certificates"
}

# Patch WebViewClient onReceivedSslError to proceed
patch_webview_ssl() {
    local decompiled_dir="$1"
    local apk_name="$2"
    log_info "Searching for WebViewClient SSL error handlers..."

    local wv_files
    wv_files=$(grep -rl "onReceivedSslError" "$decompiled_dir/smali" \
        --include="*.smali" 2>/dev/null)

    local count=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        # Replace cancel() with proceed() in onReceivedSslError
        if grep -q "->cancel()V" "$file" 2>/dev/null; then
            sed -i 's/->cancel()V/->proceed()V/g' "$file"
            count=$((count + 1))
            log_debug "Patched WebView SSL in: $file"
        fi
    done <<< "$wv_files"

    if [ "$count" -gt 0 ]; then
        SSL_PATCHES_APPLIED=$((SSL_PATCHES_APPLIED + count))
        write_finding "$apk_name" "ssl_pinning" "[WebView] Patched onReceivedSslError in ${count} file(s)"
        log_success "Patched WebView SSL handler in ${count} file(s)"
    fi
}

# Main SSL pinning bypass function
bypass_ssl_pinning() {
    local decompiled_dir="$1"
    local apk_name="$2"

    log_step "=== SSL Pinning Bypass ==="
    SSL_PATCHES_APPLIED=0

    patch_okhttp_pinner "$decompiled_dir" "$apk_name"
    patch_trustmanager "$decompiled_dir" "$apk_name"
    patch_hostname_verifier "$decompiled_dir" "$apk_name"
    patch_network_security_config "$decompiled_dir" "$apk_name"
    patch_webview_ssl "$decompiled_dir" "$apk_name"

    write_report "$apk_name" "
--- SSL Pinning Bypass ---
Total patches applied: ${SSL_PATCHES_APPLIED}
Techniques:
  - OkHttp CertificatePinner.check() neutralized
  - X509TrustManager.checkServerTrusted() neutralized
  - HostnameVerifier.verify() forced to return true
  - Network Security Config: trusts user certificates
  - WebViewClient: SSL errors proceed instead of cancel
"
    log_success "SSL Pinning Bypass complete. Patches applied: ${SSL_PATCHES_APPLIED}"
    return 0
}
