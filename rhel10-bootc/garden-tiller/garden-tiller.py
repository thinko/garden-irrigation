#!/usr/bin/env python3
"""
Garden-Tiller Main Entry Point
Lightweight version for bootable image integration
"""

import sys
import argparse
import json
from pathlib import Path

# Add the garden-tiller directory to Python path
sys.path.insert(0, '/opt/garden-tiller')

def main():
    parser = argparse.ArgumentParser(description="Garden-Tiller Network and Hardware Validation")
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Hardware inventory command
    hw_parser = subparsers.add_parser('hardware', help='Run hardware inventory')
    hw_parser.add_argument('--output', '-o', help='Output file')
    
    # Network enumeration command
    net_parser = subparsers.add_parser('network', help='Run network enumeration')
    net_parser.add_argument('--output', '-o', help='Output file')
    net_parser.add_argument('--controller-ip', help='Controller IP address')
    
    # LACP testing command
    lacp_parser = subparsers.add_parser('lacp', help='Run LACP tests')
    lacp_parser.add_argument('--output', '-o', help='Output file')
    
    # Firmware update command
    fw_parser = subparsers.add_parser('firmware', help='Check/update firmware')
    fw_parser.add_argument('--output', '-o', help='Output file')
    fw_parser.add_argument('--auto-update', action='store_true', help='Automatically update')
    
    # Full validation command
    full_parser = subparsers.add_parser('validate', help='Run full validation suite')
    full_parser.add_argument('--output-dir', '-d', default='/var/log/garden-tiller', help='Output directory')
    full_parser.add_argument('--controller-ip', help='Controller IP address')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        if args.command == 'hardware':
            from scripts.hardware_inventory import main as hw_main
            return hw_main()
        elif args.command == 'network':
            from scripts.network_enumeration import main as net_main
            return net_main()
        elif args.command == 'lacp':
            from scripts.lacp_test_runner import main as lacp_main
            return lacp_main()
        elif args.command == 'firmware':
            from scripts.firmware_updater import main as fw_main
            return fw_main()
        elif args.command == 'validate':
            return run_full_validation(args)
        else:
            print(f"Unknown command: {args.command}")
            return 1
            
    except Exception as e:
        print(f"Error: {e}")
        return 1

def run_full_validation(args):
    """Run the full validation suite"""
    import subprocess
    import time
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    timestamp = int(time.time())
    
    print("Starting Garden-Tiller full validation...")
    
    # Run hardware inventory
    print("Running hardware inventory...")
    hw_output = output_dir / f"hardware-inventory-{timestamp}.json"
    subprocess.run([
        sys.executable, "/opt/garden-tiller/scripts/hardware_inventory.py",
        "--output", str(hw_output)
    ])
    
    # Run network enumeration
    print("Running network enumeration...")
    net_output = output_dir / f"network-enumeration-{timestamp}.json"
    cmd = [
        sys.executable, "/opt/garden-tiller/scripts/network_enumeration.py",
        "--output", str(net_output)
    ]
    if args.controller_ip:
        cmd.extend(["--controller-ip", args.controller_ip])
    subprocess.run(cmd)
    
    # Run LACP tests
    print("Running LACP tests...")
    lacp_output = output_dir / f"lacp-tests-{timestamp}.json"
    subprocess.run([
        sys.executable, "/opt/garden-tiller/scripts/lacp_test_runner.py",
        "--output", str(lacp_output)
    ])
    
    # Run firmware check
    print("Checking firmware...")
    fw_output = output_dir / f"firmware-check-{timestamp}.json"
    subprocess.run([
        sys.executable, "/opt/garden-tiller/scripts/firmware_updater.py",
        "--output", str(fw_output), "--check-only"
    ])
    
    print(f"Validation complete. Results saved to {output_dir}")
    print(f"Files generated:")
    print(f"  - Hardware: {hw_output}")
    print(f"  - Network: {net_output}")
    print(f"  - LACP: {lacp_output}")
    print(f"  - Firmware: {fw_output}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
