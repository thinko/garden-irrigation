#!/bin/bash
#
# Garden-Tiller RHEL10 Bootable Image Startup Script
# Initializes the system for automated hardware enumeration and network testing
#

set -euo pipefail

# Configure logging
exec 1> >(logger -s -t garden-tiller-startup)
exec 2>&1

echo "Starting Garden-Tiller initialization..."

# Source environment configuration
if [ -f /etc/garden-tiller/environment.conf ]; then
    source /etc/garden-tiller/environment.conf
fi

# Function to wait for network interfaces
wait_for_interfaces() {
    local timeout=60
    local count=0
    
    echo "Waiting for network interfaces to be available..."
    while [ $count -lt $timeout ]; do
        if ip link show | grep -q "state UP\|state DOWN"; then
            echo "Network interfaces detected"
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    echo "Warning: Network interfaces not detected within timeout"
    return 1
}

# Function to configure basic networking
configure_networking() {
    echo "Configuring basic networking..."
    
    # Ensure NetworkManager is running
    systemctl start NetworkManager
    
    # Wait for interfaces
    wait_for_interfaces
    
    # Bring up all available interfaces
    for iface in $(ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ' | grep -v lo); do
        echo "Configuring interface: $iface"
        ip link set dev "$iface" up || true
        
        # Try DHCP on each interface (non-blocking)
        if command -v nmcli >/dev/null 2>&1; then
            nmcli device connect "$iface" 2>/dev/null || true
        fi
    done
}

# Function to start SSH service
start_ssh() {
    echo "Starting SSH service..."
    
    # Generate host keys if they don't exist
    if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
        ssh-keygen -A
    fi
    
    # Start SSH service
    systemctl start sshd
    systemctl enable sshd
    
    echo "SSH service started"
}

# Function to initialize garden-tiller environment
init_garden_tiller() {
    echo "Initializing Garden-Tiller environment..."
    
    # Create necessary directories
    mkdir -p /var/log/garden-tiller
    mkdir -p /tmp/garden-tiller-results
    
    # Set proper ownership
    chown -R ansible:ansible /opt/garden-tiller /var/log/garden-tiller /tmp/garden-tiller-results
    
    # Copy default inventory if it doesn't exist
    if [ ! -f /opt/garden-tiller/inventories/hosts.yaml ] && [ -f /etc/garden-tiller/default-inventory.yaml ]; then
        cp /etc/garden-tiller/default-inventory.yaml /opt/garden-tiller/inventories/hosts.yaml
        chown ansible:ansible /opt/garden-tiller/inventories/hosts.yaml
    fi
    
    echo "Garden-Tiller environment initialized"
}

# Function to run hardware enumeration
run_hardware_enumeration() {
    echo "Starting hardware enumeration..."
    
    # Run as ansible user
    su - ansible -c "python3 /opt/garden-tiller/scripts/hardware_inventory.py --output /var/log/garden-tiller/hardware-inventory.json" || true
    
    echo "Hardware enumeration completed"
}

# Function to start network enumeration
start_network_enumeration() {
    echo "Starting network enumeration..."
    
    # Run network discovery in background
    su - ansible -c "python3 /opt/garden-tiller/scripts/network_enumeration.py --output /var/log/garden-tiller/network-enumeration.json" &
    
    echo "Network enumeration started in background"
}

# Function to report back to controller
report_to_controller() {
    if [ -n "${CONTROLLER_IP:-}" ]; then
        echo "Attempting to report to controller at $CONTROLLER_IP"
        
        # Create status report
        cat > /tmp/status-report.json << EOF
{
    "hostname": "$(hostname)",
    "timestamp": "$(date -Iseconds)",
    "ip_addresses": [$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print "\"" $2 "\""}' | tr '\n' ',' | sed 's/,$//')],
    "status": "online",
    "services": {
        "ssh": "$(systemctl is-active sshd)",
        "network": "$(systemctl is-active NetworkManager)"
    }
}
EOF
        
        # Attempt to send report
        if command -v curl >/dev/null 2>&1; then
            curl -X POST -H "Content-Type: application/json" \
                -d @/tmp/status-report.json \
                "http://${CONTROLLER_IP}:8080/api/status" 2>/dev/null || true
        fi
        
        echo "Status report sent to controller"
    fi
}

# Main execution
main() {
    echo "=== Garden-Tiller RHEL10 Bootable Image Starting ==="
    
    # Configure basic system
    configure_networking
    start_ssh
    init_garden_tiller
    
    # Run initial enumeration
    run_hardware_enumeration
    start_network_enumeration
    
    # Report status
    report_to_controller
    
    echo "=== Garden-Tiller initialization complete ==="
    echo "System ready for automated testing and enumeration"
    echo "SSH access available on port 22"
    echo "Logs available in /var/log/garden-tiller/"
    
    # Start the init system to keep container running
    exec /usr/sbin/init
}

# Handle signals gracefully
trap 'echo "Received shutdown signal"; exit 0' TERM INT

# Run main function
main "$@"
