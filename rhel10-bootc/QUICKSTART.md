# Garden-Tiller RHEL10 Bootable Image - Quick Setup Guide

## Overview

This directory contains everything needed to build a comprehensive RHEL10 bootable image for automated hardware enumeration, network testing, and firmware updates.

## Quick Start

1. **Validate Environment:**
   ```bash
   ./validate.sh
   ```

2. **Build Image:**
   ```bash
   ./build-image.sh
   ```

3. **Deploy and Test:**
   - Use the generated ISO with IPMI virtual media
   - Or test with the QCOW2 image in a VM

## File Structure

```
rhel10-bootc/
├── Containerfile                    # Main container definition
├── requirements.txt                 # Python dependencies
├── build-image.sh                  # Image build script (executable)
├── validate.sh                     # Environment validation (executable)
├── README.md                       # Comprehensive documentation
├── QUICKSTART.md                   # This file
├── config/                         # Configuration files
│   ├── environment.conf            # Runtime environment settings
│   └── default-inventory.yaml      # Default Ansible inventory
├── scripts/                        # Core functionality scripts
│   ├── startup.sh                  # System startup script
│   ├── hardware_inventory.py       # Hardware enumeration
│   ├── network_enumeration.py      # Network testing and LACP
│   ├── firmware_updater.py         # Firmware management
│   └── lacp_test_runner.py         # LACP testing for garden-tiller
├── ansible/                        # Ansible integration
│   ├── ansible.cfg                 # Ansible configuration
│   └── network-validation.yaml     # Network validation playbook
└── garden-tiller/                  # Garden-tiller integration
    └── garden-tiller.py            # Main entry point
```

## Key Features

- **Hardware Enumeration**: Complete system inventory
- **Network Testing**: LACP, VLAN, connectivity validation  
- **Firmware Updates**: Multi-vendor firmware management
- **Garden-Tiller Integration**: Compatible with existing orchestration
- **Bootable Image**: ISO and QCOW2 formats for bare metal and VMs

## Environment Variables

Configure before building:

```bash
export CONTROLLER_IP="192.168.1.100"    # Your garden-tiller controller
export TEST_VLANS="10,20,30,100,200"    # VLANs to test
export IMAGE_NAME="my-garden-tiller"     # Custom image name
```

## Build Options

```bash
# Basic build (creates ISO)
./build-image.sh

# Create QCOW2 for VMs
./build-image.sh qcow2

# Create both ISO and QCOW2
./build-image.sh both

# Custom configuration
./build-image.sh -n custom-name -o /tmp/output iso

# Container only (no bootable conversion)
./build-image.sh --container-only

# See all options
./build-image.sh --help
```

## Testing

1. **Validate build environment:**
   ```bash
   ./validate.sh
   ```

2. **Test in VM (if QCOW2 built):**
   ```bash
   qemu-system-x86_64 -m 4096 -smp 2 -hda output/disk.qcow2
   ```

3. **Test with physical server:**
   - Mount ISO via IPMI virtual media
   - Boot and watch console for initialization
   - SSH access: `ssh ansible@<server-ip>`

## Integration with Garden-Tiller

This image works with the [garden-tiller](https://github.com/thinko/garden-tiller/) project:

1. **Compatible Scripts**: All scripts output JSON compatible with garden-tiller
2. **LACP Orchestration**: Use with `clean_boot_lacp_orchestrator.py`
3. **Ansible Integration**: Includes playbooks for garden-tiller workflows
4. **Controller Reporting**: Automatic reporting to garden-tiller controllers

## Troubleshooting

### Build Issues
- Check Red Hat subscription: `subscription-manager status`
- Verify Podman: `podman info`
- Run validation: `./validate.sh`

### Runtime Issues
- Check logs: `journalctl -f`
- Network status: `ip addr show`
- SSH access: Verify keys in `/home/ansible/.ssh/authorized_keys`

### Common Use Cases

1. **Network Lab Validation**: Boot on servers to test LACP configurations
2. **Hardware Inventory**: Quick hardware enumeration for asset management
3. **Firmware Updates**: Automated firmware checking and updates
4. **Switch Testing**: Validate switch configurations with LACP

## Next Steps

1. **Read Full Documentation**: See `README.md` for complete details
2. **Customize Configuration**: Edit files in `config/` directory
3. **Extend Functionality**: Add custom scripts to `scripts/` directory
4. **Integration**: Connect with your garden-tiller controller

## Support

- Check `README.md` for comprehensive documentation
- Validate environment with `./validate.sh`
- Build logs available in build output
- Runtime logs in `/var/log/garden-tiller/`
