#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# setup.sh - Termux Environment Setup for Android APK Modification
# =============================================================================
# Installs all required packages and tools for APK modification workflow.
# Run this script once before using modify_apk.sh.
#
# Usage: bash setup.sh
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()    { echo -e "${CYAN}[STEP]${NC} $*"; }

TOOLS_DIR="${HOME}/apk-tools"
BIN_DIR="${PREFIX}/bin"

check_termux() {
    if [ ! -d "/data/data/com.termux" ]; then
        log_error "This script must be run inside Termux."
        exit 1
    fi
}

grant_storage() {
    log_step "Requesting storage permission..."
    if [ ! -d "${HOME}/storage" ]; then
        termux-setup-storage
        sleep 3
    fi
    if [ -d "${HOME}/storage/downloads" ]; then
        log_info "Storage access granted."
    else
        log_warn "Storage may not be accessible. Run 'termux-setup-storage' manually."
    fi
}

install_base_packages() {
    log_step "Updating package repositories..."
    pkg update -y
    pkg upgrade -y

    log_step "Installing base packages..."
    local packages=(
        git
        wget
        curl
        unzip
        zip
        tar
        openssl
        openjdk-17
        aapt
        apksigner
        dx
        python
        python-pip
        binutils
        file
        grep
        sed
        coreutils
        findutils
    )

    for p in "${packages[@]}"; do
        if dpkg -s "$p" &>/dev/null; then
            log_info "Already installed: $p"
        else
            log_info "Installing: $p"
            pkg install -y "$p" || log_warn "Failed to install: $p (may be optional)"
        fi
    done
}

install_apktool() {
    log_step "Installing apktool..."
    local version
    version=$(curl -sL "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest" \
        | grep '"tag_name"' | head -1 | sed -E 's/.*"v([^"]+)".*/\1/')

    if [ -z "$version" ]; then
        version="2.9.3"
        log_warn "Could not fetch latest apktool version, using ${version}"
    fi

    local jar_path="${TOOLS_DIR}/apktool.jar"
    mkdir -p "$TOOLS_DIR"

    if [ -f "$jar_path" ]; then
        log_info "apktool.jar already exists at ${jar_path}"
    else
        log_info "Downloading apktool v${version}..."
        wget -q -O "$jar_path" \
            "https://github.com/iBotPeaches/Apktool/releases/download/v${version}/apktool_${version}.jar" \
            || { log_error "Failed to download apktool"; return 1; }
    fi

    cat > "${BIN_DIR}/apktool" << 'WRAPPER'
#!/data/data/com.termux/files/usr/bin/bash
exec java -jar "${HOME}/apk-tools/apktool.jar" "$@"
WRAPPER
    chmod +x "${BIN_DIR}/apktool"
    log_info "apktool installed successfully."
}

install_jadx() {
    log_step "Installing jadx..."
    local version
    version=$(curl -sL "https://api.github.com/repos/skylot/jadx/releases/latest" \
        | grep '"tag_name"' | head -1 | sed -E 's/.*"v([^"]+)".*/\1/')

    if [ -z "$version" ]; then
        version="1.5.0"
        log_warn "Could not fetch latest jadx version, using ${version}"
    fi

    local jadx_dir="${TOOLS_DIR}/jadx"

    if [ -d "$jadx_dir" ] && [ -f "${jadx_dir}/bin/jadx" ]; then
        log_info "jadx already installed at ${jadx_dir}"
    else
        log_info "Downloading jadx v${version}..."
        local tmpzip="/tmp/jadx.zip"
        wget -q -O "$tmpzip" \
            "https://github.com/skylot/jadx/releases/download/v${version}/jadx-${version}.zip" \
            || { log_error "Failed to download jadx"; return 1; }
        mkdir -p "$jadx_dir"
        unzip -qo "$tmpzip" -d "$jadx_dir"
        rm -f "$tmpzip"
    fi

    ln -sf "${jadx_dir}/bin/jadx" "${BIN_DIR}/jadx"
    ln -sf "${jadx_dir}/bin/jadx-gui" "${BIN_DIR}/jadx-gui" 2>/dev/null || true
    chmod +x "${jadx_dir}/bin/jadx"
    log_info "jadx installed successfully."
}

install_uber_apk_signer() {
    log_step "Installing uber-apk-signer..."
    local version
    version=$(curl -sL "https://api.github.com/repos/nicholasgasior/uber-apk-signer/releases/latest" \
        | grep '"tag_name"' | head -1 | sed -E 's/.*"v([^"]+)".*/\1/' 2>/dev/null)

    if [ -z "$version" ]; then
        version="1.3.0"
    fi

    local jar_path="${TOOLS_DIR}/uber-apk-signer.jar"
    mkdir -p "$TOOLS_DIR"

    if [ -f "$jar_path" ]; then
        log_info "uber-apk-signer.jar already exists."
    else
        log_info "Downloading uber-apk-signer..."
        wget -q -O "$jar_path" \
            "https://github.com/nicholasgasior/uber-apk-signer/releases/latest/download/uber-apk-signer.jar" 2>/dev/null \
            || log_warn "uber-apk-signer download failed; will use standard apksigner instead."
    fi
}

install_dex2jar() {
    log_step "Installing dex2jar..."
    local d2j_dir="${TOOLS_DIR}/dex2jar"

    if [ -d "$d2j_dir" ] && [ -f "${d2j_dir}/d2j-dex2jar.sh" ]; then
        log_info "dex2jar already installed."
    else
        log_info "Downloading dex2jar..."
        local tmpzip="/tmp/dex2jar.zip"
        wget -q -O "$tmpzip" \
            "https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip" \
            || { log_error "Failed to download dex2jar"; return 1; }
        mkdir -p "$d2j_dir"
        unzip -qo "$tmpzip" -d "/tmp/d2j_extract"
        mv /tmp/d2j_extract/dex-tools-v2.4/* "$d2j_dir/" 2>/dev/null \
            || mv /tmp/d2j_extract/dex-tools-2.4/* "$d2j_dir/" 2>/dev/null \
            || mv /tmp/d2j_extract/*/* "$d2j_dir/" 2>/dev/null || true
        rm -rf "$tmpzip" /tmp/d2j_extract
        chmod +x "${d2j_dir}"/*.sh 2>/dev/null || true
    fi

    ln -sf "${d2j_dir}/d2j-dex2jar.sh" "${BIN_DIR}/d2j-dex2jar" 2>/dev/null || true
    log_info "dex2jar installed successfully."
}

generate_keystore() {
    log_step "Generating debug keystore for APK signing..."
    local ks="${TOOLS_DIR}/debug.keystore"
    if [ -f "$ks" ]; then
        log_info "Debug keystore already exists."
        return
    fi

    keytool -genkeypair \
        -alias androiddebugkey \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -keystore "$ks" \
        -storepass android \
        -keypass android \
        -dname "CN=Debug,OU=Debug,O=Debug,L=Unknown,ST=Unknown,C=US" \
        2>/dev/null

    log_info "Debug keystore created at ${ks}"
}

install_python_deps() {
    log_step "Installing Python dependencies..."
    pip install --quiet --upgrade pip 2>/dev/null || true
    pip install --quiet androguard 2>/dev/null \
        || log_warn "androguard installation failed (optional for advanced analysis)"

    log_step "Installing Frida tools for runtime hooking..."
    pip install --quiet frida-tools 2>/dev/null \
        || log_warn "frida-tools installation failed (needed for runtime hooking)"
    pip install --quiet frida 2>/dev/null \
        || log_warn "frida installation failed (needed for runtime hooking)"
}

install_xz() {
    log_step "Installing xz-utils (needed to decompress frida-gadget)..."
    if command -v xz &>/dev/null; then
        log_info "xz already installed"
    else
        pkg install -y xz-utils 2>/dev/null \
            || log_warn "xz-utils installation failed (needed for frida-gadget decompression)"
    fi
}

create_output_dirs() {
    log_step "Creating output directories..."
    local base="${HOME}/storage/downloads/modify"
    mkdir -p "${base}/key"
    mkdir -p "${base}/output"
    mkdir -p "${base}/backup"
    mkdir -p "${base}/logs"
    log_info "Output directories created under ${base}/"
}

print_summary() {
    echo ""
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${GREEN}  Setup Complete!${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""
    echo -e "  Tools directory:  ${CYAN}${TOOLS_DIR}${NC}"
    echo -e "  Output directory: ${CYAN}${HOME}/storage/downloads/modify/${NC}"
    echo ""
    echo -e "  ${GREEN}Usage:${NC}"
    echo -e "    bash modify_apk.sh <path-to-apk>"
    echo -e "    bash modify_apk.sh <path-to-apk> --hook  ${CYAN}# inject runtime hooking${NC}"
    echo -e "    bash modify_apk.sh --help"
    echo ""
    echo -e "${BLUE}=========================================${NC}"
}

main() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${GREEN}  APK Modification Toolkit - Setup${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""

    check_termux
    grant_storage
    install_base_packages
    install_apktool
    install_jadx
    install_dex2jar
    install_uber_apk_signer
    generate_keystore
    install_python_deps
    install_xz
    create_output_dirs
    print_summary
}

main "$@"
