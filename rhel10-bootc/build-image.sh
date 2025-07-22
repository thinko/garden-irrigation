#!/bin/bash

set -euo pipefail

# Garden-Tiller RHEL10 Bootable Image Builder
# Builds a comprehensive diagnostic and testing image for bare metal servers

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="${IMAGE_NAME:-localhost/garden-tiller-bootc:latest}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/output}"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/build-config.toml}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! command -v podman >/dev/null 2>&1; then
        error "Podman is required but not installed"
        exit 1
    fi
    
    if ! podman info >/dev/null 2>&1; then
        error "Podman is not running or accessible"
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Login to Red Hat registry
login_registry() {
    log "Logging in to Red Hat registry..."
    
    if ! podman login registry.redhat.io; then
        error "Failed to login to Red Hat registry"
        error "Please ensure you have valid Red Hat credentials"
        exit 1
    fi
    
    success "Successfully logged in to Red Hat registry"
}

# Build the bootc container image
build_container() {
    log "Building Garden-Tiller bootc container image..."
    
    cd "${SCRIPT_DIR}"
    
    if ! podman build -t "${IMAGE_NAME}" .; then
        error "Failed to build container image"
        exit 1
    fi
    
    success "Container image built successfully: ${IMAGE_NAME}"
}

# Create configuration file
create_config() {
    log "Creating build configuration..."
    
    # Get SSH key if available
    SSH_KEY=""
    if [ -f "${HOME}/.ssh/id_rsa.pub" ]; then
        SSH_KEY=$(cat "${HOME}/.ssh/id_rsa.pub")
    elif [ -f "${HOME}/.ssh/id_ed25519.pub" ]; then
        SSH_KEY=$(cat "${HOME}/.ssh/id_ed25519.pub")
    else
        warn "No SSH public key found. SSH access will require password authentication."
    fi
    
    cat > "${CONFIG_FILE}" <<EOF
[[customizations.user]]
name = "ansible"
key = "${SSH_KEY}"
groups = ["wheel"]

[[customizations.user]]
name = "root"
key = "${SSH_KEY}"

[customizations.kernel]
append = "console=ttyS0,115200 console=tty0"

[customizations.services]
enabled = ["sshd", "NetworkManager", "chronyd", "lldpd"]

[customizations.timezone]
timezone = "UTC"

[customizations.locale]
languages = ["en_US.UTF-8"]
keyboard = "us"
EOF

    if [ -n "${SSH_KEY}" ]; then
        success "Configuration created with SSH key authentication"
    else
        warn "Configuration created without SSH key - password authentication required"
    fi
}

# Convert to bootable image format
convert_to_iso() {
    log "Converting container to bootable ISO..."
    
    # Check Podman mode before attempting conversion
    local podman_mode
    podman_mode=$(check_podman_mode)
    
    if [[ "$podman_mode" == "rootless" ]]; then
        error "Cannot create ISO in rootless mode"
        show_rootful_instructions
        return 1
    fi
    
    mkdir -p "${OUTPUT_DIR}"
    
    # Pull the bootc image builder
    if ! podman pull registry.redhat.io/rhel10/bootc-image-builder:latest; then
        error "Failed to pull bootc-image-builder"
        exit 1
    fi
    
    # Build ISO
    if ! podman run --rm -it --privileged \
        -v "${CONFIG_FILE}:/config.toml:ro" \
        -v "${OUTPUT_DIR}:/output" \
        -v /var/lib/containers/storage:/var/lib/containers/storage \
        registry.redhat.io/rhel10/bootc-image-builder:latest \
        --type iso \
        --config /config.toml \
        "${IMAGE_NAME}"; then
        error "Failed to convert to ISO"
        exit 1
    fi
    
    success "ISO image created in ${OUTPUT_DIR}"
}

# Convert to QCOW2 format
convert_to_qcow2() {
    log "Converting container to QCOW2 disk image..."
    
    # Check Podman mode before attempting conversion
    local podman_mode
    podman_mode=$(check_podman_mode)
    
    if [[ "$podman_mode" == "rootless" ]]; then
        error "Cannot create QCOW2 in rootless mode"
        show_rootful_instructions
        return 1
    fi
    
    mkdir -p "${OUTPUT_DIR}"
    
    if ! podman run --rm -it --privileged \
        -v "${CONFIG_FILE}:/config.toml:ro" \
        -v "${OUTPUT_DIR}:/output" \
        -v /var/lib/containers/storage:/var/lib/containers/storage \
        registry.redhat.io/rhel10/bootc-image-builder:latest \
        --type qcow2 \
        --config /config.toml \
        "${IMAGE_NAME}"; then
        error "Failed to convert to QCOW2"
        exit 1
    fi
    
    success "QCOW2 image created in ${OUTPUT_DIR}"
}

# Check Podman mode (rootless vs rootful)
check_podman_mode() {
    log "Checking Podman mode..."
    
    local podman_info
    if podman_info=$(podman info --format json 2>/dev/null); then
        local rootless
        rootless=$(echo "$podman_info" | jq -r '.host.security.rootless // false' 2>/dev/null || echo "unknown")
        
        if [[ "$rootless" == "true" ]]; then
            warn "Running in rootless Podman mode"
            warn "bootc-image-builder requires rootful Podman for ISO creation"
            echo "rootless"
        elif [[ "$rootless" == "false" ]]; then
            success "Running in rootful Podman mode"
            echo "rootful"
        else
            warn "Could not determine Podman mode"
            echo "unknown"
        fi
    else
        error "Failed to get Podman info"
        exit 1
    fi
}

# Display rootful conversion instructions
show_rootful_instructions() {
    echo
    echo "=== ROOTFUL PODMAN REQUIRED ==="
    echo
    echo "The bootc-image-builder requires rootful Podman to create bootable images."
    echo "You have several options:"
    echo
    echo "1. Run with sudo (recommended):"
    echo "   sudo $0 $*"
    echo
    echo "2. Use the dedicated rootful script:"
    echo "   sudo ./build-rootful.sh"
    echo
    echo "3. Switch to rootful Podman permanently:"
    echo "   sudo systemctl enable --now podman.socket"
    echo "   sudo podman build -t ${IMAGE_NAME} ."
    echo "   sudo ./build-image.sh --skip-build"
    echo
    echo "4. Manual rootful conversion:"
    echo "   sudo podman pull registry.redhat.io/rhel10/bootc-image-builder:latest"
    echo "   sudo podman run --rm -it --privileged \\"
    echo "     -v ${CONFIG_FILE}:/config.toml:ro \\"
    echo "     -v ${OUTPUT_DIR}:/output \\"
    echo "     -v /var/lib/containers/storage:/var/lib/containers/storage \\"
    echo "     registry.redhat.io/rhel10/bootc-image-builder:latest \\"
    echo "     --type iso --config /config.toml ${IMAGE_NAME}"
    echo
}

# Show usage information
usage() {
    cat <<EOF
Garden-Tiller RHEL10 Bootable Image Builder

Usage: $0 [OPTIONS] [FORMAT]

OPTIONS:
    -h, --help              Show this help message
    -n, --name NAME         Container image name (default: localhost/garden-tiller-bootc:latest)
    -o, --output DIR        Output directory (default: ./output)
    -c, --config FILE       Build configuration file (default: ./build-config.toml)
    --skip-login            Skip Red Hat registry login
    --container-only        Build container only, don't convert to bootable format

FORMATS:
    iso                     Create bootable ISO image (default)
    qcow2                   Create QCOW2 disk image for VMs
    both                    Create both ISO and QCOW2 images

EXAMPLES:
    $0                      Build ISO with default settings
    $0 qcow2                Build QCOW2 image
    $0 both                 Build both ISO and QCOW2
    $0 --container-only     Build container image only
    $0 -n my-garden-tiller -o /tmp/images iso

ENVIRONMENT VARIABLES:
    IMAGE_NAME              Container image name
    OUTPUT_DIR              Output directory
    CONFIG_FILE             Build configuration file
    CONTROLLER_IP           Garden-Tiller controller IP (for config)
    
For more information, see the README.md file.
EOF
}

# Parse command line arguments
parse_args() {
    FORMAT="iso"
    SKIP_LOGIN=false
    CONTAINER_ONLY=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -n|--name)
                IMAGE_NAME="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --skip-login)
                SKIP_LOGIN=true
                shift
                ;;
            --container-only)
                CONTAINER_ONLY=true
                shift
                ;;
            iso|qcow2|both)
                FORMAT="$1"
                shift
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Main execution
main() {
    parse_args "$@"
    
    log "Starting Garden-Tiller RHEL10 Bootable Image Build"
    log "Container Image: ${IMAGE_NAME}"
    log "Output Directory: ${OUTPUT_DIR}"
    log "Configuration File: ${CONFIG_FILE}"
    log "Format: ${FORMAT}"
    
    check_prerequisites
    
    if [ "${SKIP_LOGIN}" = false ]; then
        login_registry
    fi
    
    build_container
    
    if [ "${CONTAINER_ONLY}" = true ]; then
        success "Container build complete!"
        return 0
    fi
    
    create_config
    
    case "${FORMAT}" in
        iso)
            convert_to_iso
            ;;
        qcow2)
            convert_to_qcow2
            ;;
        both)
            convert_to_iso
            convert_to_qcow2
            ;;
        *)
            error "Invalid format: ${FORMAT}"
            exit 1
            ;;
    esac
    
    success "Build complete!"
    
    if [ -d "${OUTPUT_DIR}" ]; then
        log "Generated files:"
        ls -la "${OUTPUT_DIR}"
    fi
    
    cat <<EOF

${GREEN}Build Summary:${NC}
================
Container Image: ${IMAGE_NAME}
Output Directory: ${OUTPUT_DIR}
Format: ${FORMAT}

${YELLOW}Next Steps:${NC}
1. Test the image in a virtual environment
2. Deploy to target hardware via IPMI virtual media
3. Configure controller IP and network settings as needed

${BLUE}Usage Examples:${NC}
- Mount ISO via IPMI: Use your server's IPMI interface to mount the ISO
- Boot from QCOW2: Use with libvirt/QEMU for testing
- Network boot: Extract kernel/initrd for PXE boot environments

For detailed usage instructions, see the documentation.
EOF
}

# Run main function with all arguments
main "$@"
