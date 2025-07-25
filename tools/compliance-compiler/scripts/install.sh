#!/bin/bash
# ArdaOS Compliance Compiler Installation Script
# One-line installation: curl -fsSL https://raw.githubusercontent.com/ardaos/arda-os/main/tools/compliance-compiler/scripts/install.sh | bash

set -e

# Configuration
REPO="ardaos/arda-os"
BINARY_NAME="compliance-compiler"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="$HOME/.config/compliance-compiler"
GITHUB_API="https://api.github.com/repos/$REPO"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect OS and architecture
detect_platform() {
    local os arch

    # Detect OS
    case "$(uname -s)" in
        Linux*)     os="linux";;
        Darwin*)    os="darwin";;
        CYGWIN*|MINGW*|MSYS*) os="windows";;
        *)          log_error "Unsupported operating system: $(uname -s)"; exit 1;;
    esac

    # Detect architecture
    case "$(uname -m)" in
        x86_64|amd64)   arch="amd64";;
        aarch64|arm64)  arch="arm64";;
        *)              log_error "Unsupported architecture: $(uname -m)"; exit 1;;
    esac

    echo "${os}-${arch}"
}

# Get latest release version
get_latest_version() {
    local version

    if command_exists curl; then
        version=$(curl -fsSL "$GITHUB_API/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/compliance-compiler-v//')
    elif command_exists wget; then
        version=$(wget -qO- "$GITHUB_API/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/compliance-compiler-v//')
    else
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    if [ -z "$version" ]; then
        log_error "Failed to get latest version"
        exit 1
    fi

    echo "$version"
}

# Download and verify binary
download_binary() {
    local version="$1"
    local platform="$2"
    local download_url temp_file

    # Construct download URL
    local filename="${BINARY_NAME}-${platform}"
    if [[ "$platform" == *"windows"* ]]; then
        filename="${filename}.exe"
        download_url="https://github.com/$REPO/releases/download/compliance-compiler-v$version/${filename%.exe}.zip"
    else
        download_url="https://github.com/$REPO/releases/download/compliance-compiler-v$version/$filename.tar.gz"
    fi

    log_info "Downloading $BINARY_NAME v$version for $platform..."
    log_info "URL: $download_url"

    # Create temporary directory
    temp_file=$(mktemp -d)
    cd "$temp_file"

    # Download file
    if command_exists curl; then
        if ! curl -fsSL -o "archive" "$download_url"; then
            log_error "Failed to download binary"
            exit 1
        fi
    elif command_exists wget; then
        if ! wget -q -O "archive" "$download_url"; then
            log_error "Failed to download binary"
            exit 1
        fi
    fi

    # Extract archive
    if [[ "$platform" == *"windows"* ]]; then
        if command_exists unzip; then
            unzip -q archive
        else
            log_error "unzip command not found. Please install unzip."
            exit 1
        fi
    else
        if command_exists tar; then
            tar -xzf archive
        else
            log_error "tar command not found. Please install tar."
            exit 1
        fi
    fi

    # Find binary file
    local binary_file
    if [[ "$platform" == *"windows"* ]]; then
        binary_file=$(find . -name "${BINARY_NAME}*.exe" | head -1)
    else
        binary_file=$(find . -name "${BINARY_NAME}-*" -type f | head -1)
    fi

    if [ ! -f "$binary_file" ]; then
        log_error "Binary file not found in archive"
        exit 1
    fi

    echo "$temp_file/$binary_file"
}

# Install binary
install_binary() {
    local binary_path="$1"
    local install_path="$INSTALL_DIR/$BINARY_NAME"

    log_info "Installing $BINARY_NAME to $install_path..."

    # Check if install directory exists and is writable
    if [ ! -d "$INSTALL_DIR" ]; then
        log_info "Creating install directory: $INSTALL_DIR"
        if ! sudo mkdir -p "$INSTALL_DIR"; then
            log_error "Failed to create install directory"
            exit 1
        fi
    fi

    # Install binary
    if ! sudo cp "$binary_path" "$install_path"; then
        log_error "Failed to install binary"
        exit 1
    fi

    # Make executable
    if ! sudo chmod +x "$install_path"; then
        log_error "Failed to make binary executable"
        exit 1
    fi

    log_success "Binary installed to $install_path"
}

# Create configuration directory
create_config() {
    log_info "Creating configuration directory: $CONFIG_DIR"

    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
    fi

    # Create default configuration file
    cat > "$CONFIG_DIR/config.yaml" << 'EOF'
# ArdaOS Compliance Compiler Configuration
version: "1.0.0"

# Default compilation settings
compilation:
  output_format: "protobuf"
  validation_strict: true
  optimization_level: "standard"

# Template settings
templates:
  auto_update: true
  repository: "https://github.com/ardaos/arda-os/tree/main/tools/compliance-compiler/examples/templates"

# Logging configuration
logging:
  level: "info"
  format: "text"
  output: "stdout"

# Integration settings
integration:
  ardaos_modules: true
  external_systems: false
EOF

    log_success "Configuration created at $CONFIG_DIR/config.yaml"
}

# Verify installation
verify_installation() {
    local install_path="$INSTALL_DIR/$BINARY_NAME"

    log_info "Verifying installation..."

    if [ ! -f "$install_path" ]; then
        log_error "Binary not found at $install_path"
        exit 1
    fi

    if [ ! -x "$install_path" ]; then
        log_error "Binary is not executable"
        exit 1
    fi

    # Test binary execution
    if ! "$install_path" --version >/dev/null 2>&1; then
        log_error "Binary execution failed"
        exit 1
    fi

    local version
    version=$("$install_path" --version 2>/dev/null | head -1 | awk '{print $NF}')

    log_success "Installation verified successfully!"
    log_success "ArdaOS Compliance Compiler version: $version"
}

# Add to PATH if needed
update_path() {
    local shell_rc

    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        log_info "Adding $INSTALL_DIR to PATH..."

        # Detect shell and update appropriate rc file
        case "$SHELL" in
            */bash)  shell_rc="$HOME/.bashrc";;
            */zsh)   shell_rc="$HOME/.zshrc";;
            */fish)  shell_rc="$HOME/.config/fish/config.fish";;
            *)       shell_rc="$HOME/.profile";;
        esac

        if [ -f "$shell_rc" ]; then
            echo "" >> "$shell_rc"
            echo "# Added by compliance-compiler installer" >> "$shell_rc"
            echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$shell_rc"
            log_success "Added $INSTALL_DIR to PATH in $shell_rc"
            log_info "Please run 'source $shell_rc' or restart your shell"
        else
            log_warning "Could not automatically update PATH. Please add $INSTALL_DIR to your PATH manually."
        fi
    fi
}

# Show usage information
show_usage() {
    log_success "Installation complete!"
    echo ""
    echo "Usage examples:"
    echo "  $BINARY_NAME --help                           # Show help"
    echo "  $BINARY_NAME --version                        # Show version"
    echo "  $BINARY_NAME validate policy.yaml             # Validate a policy"
    echo "  $BINARY_NAME compile policy.yaml              # Compile a policy"
    echo "  $BINARY_NAME generate --type credit-card      # Generate template"
    echo ""
    echo "Configuration:"
    echo "  Config file: $CONFIG_DIR/config.yaml"
    echo "  Examples: https://github.com/$REPO/tree/main/tools/compliance-compiler/examples"
    echo ""
    echo "Documentation:"
    echo "  https://docs.ardaos.com/compliance-compiler"
    echo ""
}

# Main installation function
main() {
    local version platform binary_path

    echo "ArdaOS Compliance Compiler Installer"
    echo "====================================="
    echo ""

    # Check prerequisites
    if ! command_exists curl && ! command_exists wget; then
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    # Detect platform
    platform=$(detect_platform)
    log_info "Detected platform: $platform"

    # Get latest version
    version=$(get_latest_version)
    log_info "Latest version: v$version"

    # Check if already installed
    if command_exists "$BINARY_NAME"; then
        local current_version
        current_version=$($BINARY_NAME --version 2>/dev/null | head -1 | awk '{print $NF}' || echo "unknown")

        if [ "$current_version" = "$version" ]; then
            log_success "$BINARY_NAME v$version is already installed"
            exit 0
        else
            log_info "Upgrading from v$current_version to v$version"
        fi
    fi

    # Download binary
    binary_path=$(download_binary "$version" "$platform")

    # Install binary
    install_binary "$binary_path"

    # Create configuration
    create_config

    # Verify installation
    verify_installation

    # Update PATH
    update_path

    # Cleanup
    rm -rf "$(dirname "$binary_path")"

    # Show usage
    show_usage
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        cat << 'EOF'
ArdaOS Compliance Compiler Installer

Usage: install.sh [OPTIONS]

Options:
  --help, -h         Show this help message
  --version, -v      Install specific version
  --dir DIR          Install to specific directory (default: /usr/local/bin)
  --no-config        Skip configuration creation
  --no-path          Skip PATH update

Examples:
  curl -fsSL https://raw.githubusercontent.com/ardaos/arda-os/main/tools/compliance-compiler/scripts/install.sh | bash
  ./install.sh --version 1.2.3
  ./install.sh --dir /opt/bin

EOF
        exit 0
        ;;
    --version|-v)
        if [ -n "${2:-}" ]; then
            VERSION="$2"
            shift
        else
            log_error "Version not specified"
            exit 1
        fi
        ;;
    --dir)
        if [ -n "${2:-}" ]; then
            INSTALL_DIR="$2"
            shift
        else
            log_error "Directory not specified"
            exit 1
        fi
        ;;
    --no-config)
        SKIP_CONFIG=true
        ;;
    --no-path)
        SKIP_PATH=true
        ;;
esac

# Run main installation
main "$@"
