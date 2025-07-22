# Garden-Tiller RHEL10 Bootable Image

A comprehensive, lightweight RHEL10 image-mode bootable Linux image designed for automated hardware enumeration, network testing, and firmware updates. This image is specifically built to facilitate testing of LACP configurations, VLAN setups, network connectivity, and hardware validation in bare metal environments.

## Features

### 🔧 Hardware Enumeration
- Complete system inventory (CPU, memory, storage, network interfaces)
- BMC/IPMI discovery and monitoring
- PCI device enumeration
- Firmware version detection
- Smart disk health monitoring

### 🌐 Network Testing & Validation
- Comprehensive network interface discovery
- LACP bonding mode testing (802.3ad, active-backup, balance-xor, broadcast)
- VLAN configuration testing
- Network topology discovery via LLDP
- Connectivity validation (ping, DNS, HTTP/HTTPS)
- Switch compatibility testing

### 🔄 Firmware Management
- Automated firmware update detection
- Support for multiple vendors (Dell, HP, Lenovo, Intel, Broadcom)
- BIOS/UEFI, BMC, network card, and storage firmware
- Security update prioritization
- fwupd integration

### 📊 Integration with Garden-Tiller
- Compatible with [garden-tiller](https://github.com/thinko/garden-tiller/) orchestration
- Automated reporting to controller systems
- JSON-based result output for automation
- Ansible playbook integration

## Quick Start

### Prerequisites
- RHEL-based system with Podman
- Valid Red Hat subscription for registry access
- SSH key pair (recommended)
- 4GB+ available storage for image build

### Build the Image

1. **Clone or download this project:**
   ```bash
   # If using from garden-irrigation project
   cd rhel10-bootc/
   ```

2. **Build the image:**
   ```bash
   # Build ISO image (default)
   ./build-image.sh
   
   # Build QCOW2 for VMs
   ./build-image.sh qcow2
   
   # Build both formats
   ./build-image.sh both
   
   # Build with custom name
   ./build-image.sh -n my-garden-tiller iso
   ```

3. **Deploy the image:**
   - **Physical Servers:** Use the generated ISO with IPMI virtual media
   - **Virtual Machines:** Use the QCOW2 image with libvirt/QEMU
   - **Testing:** Boot from USB or virtual CD

## Configuration

### Environment Variables

Set these variables before building or at runtime:

```bash
# Controller configuration
export CONTROLLER_IP="192.168.1.100"
export CONTROLLER_PORT="8080"

# Network testing configuration
export TEST_VLANS="10,20,30,100,200"
export TEST_SUBNETS="192.168.1.0/24,10.0.0.0/24"

# Build configuration
export IMAGE_NAME="my-garden-tiller:latest"
export OUTPUT_DIR="/tmp/bootable-images"
```

### Runtime Configuration

The image can be configured via environment variables or configuration files:

```bash
# Example: Boot with controller IP
# Add to kernel command line: CONTROLLER_IP=192.168.1.100
```

## Usage Examples

### 1. Hardware Inventory
```bash
# On the booted system
garden-tiller hardware --output /tmp/hardware-report.json

# Or directly
python3 /opt/garden-tiller/scripts/hardware_inventory.py --verbose
```

### 2. Network Enumeration and Testing
```bash
# Basic network discovery
garden-tiller network --output /tmp/network-report.json

# With controller reporting
garden-tiller network --controller-ip 192.168.1.100
```

### 3. LACP Testing
```bash
# Test all LACP configurations
garden-tiller lacp --output /tmp/lacp-results.json

# Compatible with garden-tiller orchestrator
python3 /opt/garden-tiller/scripts/clean_boot_lacp_orchestrator.py
```

### 4. Firmware Management
```bash
# Check for firmware updates
garden-tiller firmware --output /tmp/firmware-status.json

# Auto-update firmware (use with caution)
garden-tiller firmware --auto-update
```

### 5. Full Validation Suite
```bash
# Run all tests
garden-tiller validate --output-dir /var/log/garden-tiller --controller-ip 192.168.1.100
```

## Integration with Garden-Tiller

This image is designed to work seamlessly with the [garden-tiller](https://github.com/thinko/garden-tiller/) project:

1. **Orchestrated Testing:** Use with `clean_boot_lacp_orchestrator.py` for comprehensive LACP validation
2. **Automated Reporting:** Results are automatically sent to the garden-tiller controller
3. **Ansible Integration:** Includes playbooks compatible with garden-tiller workflows
4. **JSON Output:** All tools output JSON for easy integration with automation systems

### Example: Integration with Garden-Tiller Controller

```yaml
# Ansible inventory entry
all:
  hosts:
    test-server-01:
      ansible_host: 192.168.1.101
      bmc_address: 192.168.1.201
      bmc_type: idrac
      controller_ip: 192.168.1.100
```

## Architecture

### Directory Structure
```
/opt/garden-tiller/
├── scripts/
│   ├── hardware_inventory.py      # Hardware enumeration
│   ├── network_enumeration.py     # Network testing
│   ├── lacp_test_runner.py        # LACP validation
│   └── firmware_updater.py        # Firmware management
├── ansible/
│   ├── ansible.cfg                # Ansible configuration
│   └── network-validation.yaml    # Network validation playbook
├── inventories/
│   └── hosts.yaml                 # Default inventory
└── garden-tiller.py               # Main entry point
```

### Key Components

1. **Hardware Inventory Script**: Uses dmidecode, lshw, lspci, and other tools for comprehensive hardware discovery
2. **Network Enumeration**: Discovers interfaces, tests bonding modes, validates VLAN configurations
3. **LACP Test Runner**: Focused LACP testing compatible with the garden-tiller orchestrator
4. **Firmware Updater**: Multi-vendor firmware update detection and management
5. **Startup Script**: Automatic initialization and controller reporting

## Network Testing Capabilities

### LACP Modes Tested
- **802.3ad (LACP)**: Dynamic link aggregation with partner negotiation
- **active-backup**: Active/passive failover bonding
- **balance-xor**: XOR-based load balancing
- **broadcast**: Broadcast on all interfaces
- **balance-tlb**: Transmit load balancing
- **balance-alb**: Adaptive load balancing

### VLAN Testing
- Automatic VLAN interface creation
- DHCP testing on VLAN interfaces
- VLAN tag validation
- Support for multiple VLAN ranges

### Connectivity Testing
- Internet connectivity (DNS, ping)
- Controller reachability
- Custom target testing
- Latency measurement

## Supported Hardware

### Vendors
- **Dell**: iDRAC integration, Dell Update Packages (DUP)
- **HP/HPE**: iLO support, Smart Update Manager compatibility
- **Lenovo**: ThinkSystem Update Suite integration
- **Intel**: Network cards, storage controllers
- **Broadcom**: Network interface firmware

### BMC Support
- IPMI-compliant BMCs
- Dell iDRAC (all versions)
- HP/HPE iLO (v3+)
- Supermicro BMCs
- Generic Redfish-compatible BMCs

## Security Features

- Minimal attack surface with only required packages
- SSH key-based authentication (password auth disabled by default)
- Firewall configuration
- Secure firmware update validation
- Encrypted communication with controllers
- Audit logging for all operations

## Troubleshooting

### Common Issues

1. **Build Failures:**
   ```bash
   # Check Red Hat subscription
   subscription-manager status
   
   # Verify Podman configuration
   podman info
   ```

2. **Network Interface Issues:**
   ```bash
   # Check interface status
   ip link show
   
   # Verify driver loading
   lsmod | grep bonding
   ```

3. **SSH Access:**
   ```bash
   # Check SSH service
   systemctl status sshd
   
   # Verify keys
   cat /home/ansible/.ssh/authorized_keys
   ```

### Debugging

Enable verbose logging:
```bash
export LOG_LEVEL=DEBUG
garden-tiller validate --verbose
```

Check system logs:
```bash
journalctl -f -u garden-tiller
tail -f /var/log/garden-tiller/
```

## Performance Considerations

### Resource Requirements
- **Minimum RAM**: 2GB (4GB recommended)
- **Storage**: 1GB for base image
- **Network**: 1Gbps+ for optimal testing
- **CPU**: 2+ cores recommended for parallel testing

### Optimization Tips
1. **Parallel Testing**: Adjust `max_workers` in scripts for concurrent operations
2. **Network Timeouts**: Tune timeout values for slow networks
3. **Logging**: Reduce log verbosity in production environments
4. **Firmware Updates**: Schedule updates during maintenance windows

## Contributing

This project follows enterprise coding standards and security practices:

1. **Security First**: All inputs validated, outputs sanitized
2. **Error Handling**: Comprehensive error handling with graceful fallbacks
3. **Logging**: Structured logging with appropriate levels
4. **Testing**: Unit tests for critical functions
5. **Documentation**: Complete API documentation

### Development Environment

```bash
# Set up development environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
python -m pytest tests/

# Code quality checks
pylint scripts/
black scripts/
```

## License

This project is distributed under the same license as the garden-tiller project (BSD 3-Clause).

## Support

For issues and questions:

1. **Garden-Tiller Issues**: [GitHub Issues](https://github.com/thinko/garden-tiller/issues)
2. **RHEL/Bootc**: Red Hat support channels
3. **Hardware-specific**: Vendor support documentation

## Roadmap

### Planned Features
- [ ] Enhanced GPU firmware support
- [ ] Storage controller RAID configuration
- [ ] Advanced network topology mapping
- [ ] Container orchestration platform testing
- [ ] Enhanced vendor-specific BMC features
- [ ] Performance benchmarking integration

### Integration Improvements
- [ ] Grafana dashboard integration
- [ ] Prometheus metrics export
- [ ] Slack/Teams notification support
- [ ] GitOps integration for configuration management

---

**Note**: This image is designed for testing and validation environments. Always review and test in non-production environments before deploying to critical infrastructure.
