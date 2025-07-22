#!/bin/bash
# RHEL Subscription Setup Script for Container Build
# This script handles Red Hat subscription registration and repository enablement

set -euo pipefail

# Configuration - Replace these with your actual Red Hat credentials
ACTIVATION_KEY="YOUR_ACTIVATION_KEY"
ORG_ID="YOUR_ORG_ID"
MAX_RETRIES=3
RETRY_DELAY=10

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Clean any existing subscription data
cleanup_subscription() {
    log "Cleaning existing subscription data..."
    subscription-manager clean || true
    subscription-manager remove --all || true
}

# Register with Red Hat using activation key
register_subscription() {
    local attempt=1
    
    while [ $attempt -le $MAX_RETRIES ]; do
        log "Registration attempt $attempt/$MAX_RETRIES..."
        
        if subscription-manager register \
            --activationkey="$ACTIVATION_KEY" \
            --org="$ORG_ID" \
            --force; then
            log "Registration successful"
            return 0
        else
            log "Registration attempt $attempt failed"
            if [ $attempt -lt $MAX_RETRIES ]; then
                log "Waiting $RETRY_DELAY seconds before retry..."
                sleep $RETRY_DELAY
            fi
            ((attempt++))
        fi
    done
    
    log "ERROR: All registration attempts failed"
    return 1
}

# Auto-attach subscriptions
attach_subscriptions() {
    log "Auto-attaching subscriptions..."
    if subscription-manager attach --auto; then
        log "Auto-attach successful"
        return 0
    else
        log "WARNING: Auto-attach failed, checking available subscriptions..."
        subscription-manager list --available
        return 1
    fi
}

# Enable required repositories
enable_repositories() {
    log "Enabling required repositories..."
    
    # Critical repositories that must be enabled
    local critical_repos=(
        "rhel-10-for-x86_64-baseos-rpms"
        "rhel-10-for-x86_64-appstream-rpms"
    )
    
    # Optional repositories
    local optional_repos=(
        "rhel-10-for-x86_64-supplementary-rpms"
        "codeready-builder-for-rhel-10-x86_64-rpms"
        "rhel-10-for-x86_64-highavailability-rpms"
    )
    
    # Enable critical repositories
    for repo in "${critical_repos[@]}"; do
        log "Enabling critical repository: $repo"
        if ! subscription-manager repos --enable "$repo"; then
            log "ERROR: Failed to enable critical repository: $repo"
            log "Available repositories:"
            subscription-manager repos --list
            return 1
        fi
    done
    
    # Enable optional repositories (failures are warnings)
    for repo in "${optional_repos[@]}"; do
        log "Attempting to enable optional repository: $repo"
        if subscription-manager repos --enable "$repo"; then
            log "Successfully enabled optional repository: $repo"
        else
            log "WARNING: Could not enable optional repository: $repo"
        fi
    done
}

# Verify repository access
verify_repositories() {
    log "Verifying repository access..."
    
    # List enabled repositories
    log "Currently enabled repositories:"
    subscription-manager repos --list-enabled
    
    # Test repository access
    log "Testing repository metadata refresh..."
    if dnf makecache --refresh; then
        log "Repository verification successful"
        return 0
    else
        log "WARNING: Some repositories may not be accessible"
        log "Available DNF repositories:"
        dnf repolist all
        return 1
    fi
}

# Check for UBI fallback
check_ubi_fallback() {
    log "Checking for UBI repository fallback..."
    if dnf repolist | grep -q ubi; then
        log "UBI repositories detected and available as fallback"
        return 0
    else
        log "No UBI repositories available"
        return 1
    fi
}

# Main execution
main() {
    log "Starting Red Hat subscription setup..."
    
    # Step 1: Clean existing subscriptions
    cleanup_subscription
    
    # Step 2: Register subscription
    if ! register_subscription; then
        log "Registration failed, checking for fallback options..."
        if check_ubi_fallback; then
            log "Continuing with UBI repositories"
            return 0
        else
            log "No fallback available, exiting"
            return 1
        fi
    fi
    
    # Step 3: Attach subscriptions
    if ! attach_subscriptions; then
        log "Auto-attach failed, checking manual subscription options..."
        subscription-manager list --consumed
    fi
    
    # Step 4: Enable repositories
    if ! enable_repositories; then
        log "Repository enablement failed"
        return 1
    fi
    
    # Step 5: Verify access
    verify_repositories
    
    log "Subscription setup completed successfully"
}

# Execute main function
main "$@"
