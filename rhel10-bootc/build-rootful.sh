#!/bin/bash
# Rootful Podman Setup and Build Script for RHEL10 Bootc Image

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Check Podman mode
check_podman_mode() {
    local podman_info
    podman_info=$(podman info --format json 2>/dev/null) || {
        error "Failed to get Podman info"
        return 1
    }
    
    local rootless
    rootless=$(echo "$podman_info" | jq -r '.host.security.rootless // false')
    
    if [[ "$rootless" == "true" ]]; then
        echo "rootless"
    else
        echo "rootful"
    fi
}

# Setup rootful Podman
setup_rootful_podman() {
    log "Setting up rootful Podman..."
    
    # Enable podman socket for root
    sudo systemctl enable --now podman.socket || {
        warn "Failed to enable podman socket"
    }
    
    # Start podman service
    sudo systemctl enable --now podman || {
        warn "Failed to enable podman service"
    }
    
    success "Rootful Podman setup completed"
}

# Build container image with rootful Podman
build_container_rootful() {
    local script_dir="$1"
    local image_name="$2"
    
    log "Building container image with rootful Podman..."
    
    if sudo podman build -t "$image_name" "$script_dir"; then
        success "Container image built successfully: $image_name"
        return 0
    else
        error "Failed to build container image"
        return 1
    fi
}

# Convert to ISO with rootful Podman
convert_to_iso_rootful() {
    local image_name="$1"
    local output_dir="$2"
    local config_file="$3"
    
    log "Converting to ISO with rootful Podman..."
    
    # Create output directory
    sudo mkdir -p "$output_dir"
    
    # Pull bootc-image-builder
    log "Pulling bootc-image-builder..."
    if ! sudo podman pull registry.redhat.io/rhel10/bootc-image-builder:latest; then
        error "Failed to pull bootc-image-builder"
        return 1
    fi
    
    # Build ISO
    log "Building ISO image..."
    if sudo podman run --rm -it --privileged \
        -v "$config_file:/config.toml:ro" \
        -v "$output_dir:/output" \
        -v /var/lib/containers/storage:/var/lib/containers/storage \
        registry.redhat.io/rhel10/bootc-image-builder:latest \
        --type iso \
        --config /config.toml \
        "$image_name"; then
        success "ISO image created in $output_dir"
        return 0
    else
        error "Failed to convert to ISO"
        return 1
    fi
}

# Alternative: Use systemd-nspawn for rootless operation
build_with_systemd_nspawn() {
    local script_dir="$1"
    local image_name="$2"
    local output_dir="$3"
    
    log "Attempting alternative build with systemd-nspawn..."
    
    warn "This is an experimental approach using systemd-nspawn"
    warn "Consider using rootful Podman for production builds"
    
    # Export container to tar
    local container_tar="$output_dir/container.tar"
    mkdir -p "$output_dir"
    
    if podman save "$image_name" -o "$container_tar"; then
        success "Container exported to $container_tar"
    else
        error "Failed to export container"
        return 1
    fi
    
    # Use podman export instead for filesystem
    local container_id
    container_id=$(podman create "$image_name")
    
    if podman export "$container_id" | sudo tar -xf - -C "$output_dir"; then
        success "Container filesystem extracted to $output_dir"
        podman rm "$container_id"
    else
        error "Failed to extract container filesystem"
        podman rm "$container_id" || true
        return 1
    fi
}

# Main execution function
main() {
    local script_dir="${1:-$(pwd)}"
    local image_name="${2:-localhost/garden-tiller-bootc:latest}"
    local output_dir="${3:-${script_dir}/output}"
    local config_file="${4:-${script_dir}/build-config.toml}"
    
    log "Starting rootful Podman build process..."
    log "Script directory: $script_dir"
    log "Image name: $image_name"
    log "Output directory: $output_dir"
    log "Config file: $config_file"
    
    # Check current Podman mode
    local current_mode
    current_mode=$(check_podman_mode)
    log "Current Podman mode: $current_mode"
    
    # Option 1: If we're already root, proceed directly
    if check_root; then
        log "Running as root, proceeding with rootful Podman..."
        
        setup_rootful_podman
        
        if build_container_rootful "$script_dir" "$image_name"; then
            convert_to_iso_rootful "$image_name" "$output_dir" "$config_file"
        fi
        
    # Option 2: If we're not root, provide instructions and alternatives
    else
        warn "Not running as root. bootc-image-builder requires rootful Podman."
        
        echo
        echo "=== SOLUTIONS ==="
        echo
        echo "1. Run this script with sudo:"
        echo "   sudo $0 $*"
        echo
        echo "2. Switch to rootful Podman permanently:"
        echo "   sudo systemctl enable --now podman.socket"
        echo "   sudo podman build -t $image_name $script_dir"
        echo "   sudo podman run --rm -it --privileged \\"
        echo "     -v $config_file:/config.toml:ro \\"
        echo "     -v $output_dir:/output \\"
        echo "     -v /var/lib/containers/storage:/var/lib/containers/storage \\"
        echo "     registry.redhat.io/rhel10/bootc-image-builder:latest \\"
        echo "     --type iso --config /config.toml $image_name"
        echo
        echo "3. Use container export (alternative method):"
        echo "   This will export the container filesystem instead of creating a bootable ISO"
        echo
        
        read -p "Do you want to try the container export method? (y/n): " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            build_with_systemd_nspawn "$script_dir" "$image_name" "$output_dir"
        else
            warn "Please run with sudo or use rootful Podman to build bootable images"
            exit 1
        fi
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
