#!/usr/bin/env python3
"""
Garden-Tiller Hardware Inventory Script
Comprehensive hardware enumeration for bare metal systems
"""

import json
import subprocess
import sys
import time
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="ISO"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

@dataclass
class SystemInfo:
    """System basic information"""
    hostname: str
    kernel: str
    architecture: str
    uptime: float
    boot_time: str

@dataclass
class CPUInfo:
    """CPU information"""
    model: str
    cores: int
    threads: int
    frequency: float
    flags: List[str]
    cache_sizes: Dict[str, str]

@dataclass
class MemoryInfo:
    """Memory information"""
    total: int
    available: int
    speed: Optional[str]
    type: Optional[str]
    modules: List[Dict[str, Any]]

@dataclass
class StorageDevice:
    """Storage device information"""
    device: str
    size: int
    model: str
    type: str
    interface: str
    smart_status: Optional[str]
    partitions: List[Dict[str, Any]]

@dataclass
class NetworkInterface:
    """Network interface information"""
    name: str
    mac_address: str
    driver: str
    speed: Optional[str]
    duplex: Optional[str]
    state: str
    pci_id: Optional[str]

@dataclass
class PCIDevice:
    """PCI device information"""
    slot: str
    device_class: str
    vendor: str
    device: str
    driver: Optional[str]

@dataclass
class BMCInfo:
    """BMC/IPMI information"""
    present: bool
    version: Optional[str]
    manufacturer: Optional[str]
    ip_address: Optional[str]
    mac_address: Optional[str]

@dataclass
class HardwareInventory:
    """Complete hardware inventory"""
    timestamp: str
    system: SystemInfo
    cpu: CPUInfo
    memory: MemoryInfo
    storage: List[StorageDevice]
    network: List[NetworkInterface]
    pci_devices: List[PCIDevice]
    bmc: BMCInfo
    firmware: Dict[str, Any]

class HardwareEnumerator:
    """Hardware enumeration class"""
    
    def __init__(self):
        self.logger = structlog.get_logger(self.__class__.__name__)
    
    def run_command(self, cmd: List[str], ignore_errors: bool = True) -> Optional[str]:
        """Run a system command and return output"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            if not ignore_errors:
                self.logger.error("Command failed", cmd=" ".join(cmd), error=str(e))
            return None
        except FileNotFoundError:
            if not ignore_errors:
                self.logger.error("Command not found", cmd=" ".join(cmd))
            return None
    
    def get_system_info(self) -> SystemInfo:
        """Get basic system information"""
        hostname = self.run_command(["hostname"]) or "unknown"
        kernel = self.run_command(["uname", "-r"]) or "unknown"
        arch = self.run_command(["uname", "-m"]) or "unknown"
        
        # Get uptime
        uptime_str = self.run_command(["cat", "/proc/uptime"])
        uptime = float(uptime_str.split()[0]) if uptime_str else 0.0
        
        # Get boot time
        boot_time = self.run_command(["uptime", "-s"]) or "unknown"
        
        return SystemInfo(
            hostname=hostname,
            kernel=kernel,
            architecture=arch,
            uptime=uptime,
            boot_time=boot_time
        )
    
    def get_cpu_info(self) -> CPUInfo:
        """Get CPU information"""
        try:
            with open("/proc/cpuinfo", "r") as f:
                cpuinfo = f.read()
        except IOError:
            cpuinfo = ""
        
        # Parse CPU info
        model = "unknown"
        cores = 0
        threads = 0
        frequency = 0.0
        flags = []
        
        for line in cpuinfo.split('\n'):
            if line.startswith('model name'):
                model = line.split(':', 1)[1].strip()
            elif line.startswith('cpu cores'):
                cores = int(line.split(':', 1)[1].strip())
            elif line.startswith('siblings'):
                threads = int(line.split(':', 1)[1].strip())
            elif line.startswith('cpu MHz'):
                frequency = float(line.split(':', 1)[1].strip())
            elif line.startswith('flags'):
                flags = line.split(':', 1)[1].strip().split()
        
        # Get cache information
        cache_sizes = {}
        lscpu_output = self.run_command(["lscpu"])
        if lscpu_output:
            for line in lscpu_output.split('\n'):
                if 'cache:' in line.lower():
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        cache_sizes[parts[0].strip()] = parts[1].strip()
        
        return CPUInfo(
            model=model,
            cores=cores,
            threads=threads,
            frequency=frequency,
            flags=flags,
            cache_sizes=cache_sizes
        )
    
    def get_memory_info(self) -> MemoryInfo:
        """Get memory information"""
        try:
            with open("/proc/meminfo", "r") as f:
                meminfo = f.read()
        except IOError:
            meminfo = ""
        
        total = 0
        available = 0
        
        for line in meminfo.split('\n'):
            if line.startswith('MemTotal:'):
                total = int(line.split()[1]) * 1024  # Convert from KB to bytes
            elif line.startswith('MemAvailable:'):
                available = int(line.split()[1]) * 1024
        
        # Get memory module information from dmidecode
        modules = []
        dmidecode_output = self.run_command(["dmidecode", "-t", "memory"])
        if dmidecode_output:
            current_module = {}
            for line in dmidecode_output.split('\n'):
                line = line.strip()
                if line.startswith('Size:') and 'No Module Installed' not in line:
                    current_module['size'] = line.split(':', 1)[1].strip()
                elif line.startswith('Speed:'):
                    current_module['speed'] = line.split(':', 1)[1].strip()
                elif line.startswith('Type:'):
                    current_module['type'] = line.split(':', 1)[1].strip()
                elif line.startswith('Manufacturer:'):
                    current_module['manufacturer'] = line.split(':', 1)[1].strip()
                elif line == '' and current_module:
                    modules.append(current_module)
                    current_module = {}
        
        # Extract speed and type from first module
        speed = modules[0].get('speed') if modules else None
        mem_type = modules[0].get('type') if modules else None
        
        return MemoryInfo(
            total=total,
            available=available,
            speed=speed,
            type=mem_type,
            modules=modules
        )
    
    def get_storage_info(self) -> List[StorageDevice]:
        """Get storage device information"""
        devices = []
        
        # Get block devices
        lsblk_output = self.run_command(["lsblk", "-J", "-o", "NAME,SIZE,MODEL,TYPE,FSTYPE"])
        if lsblk_output:
            try:
                lsblk_data = json.loads(lsblk_output)
                for device in lsblk_data.get('blockdevices', []):
                    if device.get('type') == 'disk':
                        # Get additional device info
                        dev_path = f"/dev/{device['name']}"
                        
                        # Get SMART status
                        smart_status = None
                        smartctl_output = self.run_command(["smartctl", "-H", dev_path])
                        if smartctl_output and "PASSED" in smartctl_output:
                            smart_status = "PASSED"
                        elif smartctl_output and "FAILED" in smartctl_output:
                            smart_status = "FAILED"
                        
                        # Get interface type
                        interface = "unknown"
                        if "nvme" in device['name']:
                            interface = "NVMe"
                        elif "sd" in device['name']:
                            interface = "SATA/SAS"
                        
                        # Get partitions
                        partitions = []
                        for child in device.get('children', []):
                            partitions.append({
                                'name': child['name'],
                                'size': child.get('size', ''),
                                'fstype': child.get('fstype', '')
                            })
                        
                        devices.append(StorageDevice(
                            device=device['name'],
                            size=self._parse_size(device.get('size', '0')),
                            model=device.get('model', 'unknown'),
                            type=device.get('type', 'unknown'),
                            interface=interface,
                            smart_status=smart_status,
                            partitions=partitions
                        ))
            except json.JSONDecodeError:
                self.logger.error("Failed to parse lsblk output")
        
        return devices
    
    def get_network_interfaces(self) -> List[NetworkInterface]:
        """Get network interface information"""
        interfaces = []
        
        # Get interface list
        ip_output = self.run_command(["ip", "link", "show"])
        if not ip_output:
            return interfaces
        
        for line in ip_output.split('\n'):
            if ': <' in line and 'lo:' not in line:
                # Parse interface name
                parts = line.split(':', 2)
                if len(parts) >= 2:
                    iface_name = parts[1].strip()
                    
                    # Get MAC address
                    mac_addr = "unknown"
                    if 'link/ether' in line:
                        mac_parts = line.split('link/ether')[1].split()
                        if mac_parts:
                            mac_addr = mac_parts[0]
                    
                    # Get interface state
                    state = "DOWN"
                    if "state UP" in line:
                        state = "UP"
                    elif "state DOWN" in line:
                        state = "DOWN"
                    
                    # Get ethtool information
                    driver = "unknown"
                    speed = None
                    duplex = None
                    
                    ethtool_output = self.run_command(["ethtool", "-i", iface_name])
                    if ethtool_output:
                        for ethtool_line in ethtool_output.split('\n'):
                            if ethtool_line.startswith('driver:'):
                                driver = ethtool_line.split(':', 1)[1].strip()
                    
                    ethtool_speed = self.run_command(["ethtool", iface_name])
                    if ethtool_speed:
                        for speed_line in ethtool_speed.split('\n'):
                            if 'Speed:' in speed_line:
                                speed = speed_line.split(':', 1)[1].strip()
                            elif 'Duplex:' in speed_line:
                                duplex = speed_line.split(':', 1)[1].strip()
                    
                    # Get PCI ID
                    pci_id = None
                    try:
                        readlink_output = self.run_command(["readlink", "-f", f"/sys/class/net/{iface_name}/device"])
                        if readlink_output and "pci" in readlink_output:
                            pci_id = readlink_output.split('/')[-1]
                    except:
                        pass
                    
                    interfaces.append(NetworkInterface(
                        name=iface_name,
                        mac_address=mac_addr,
                        driver=driver,
                        speed=speed,
                        duplex=duplex,
                        state=state,
                        pci_id=pci_id
                    ))
        
        return interfaces
    
    def get_pci_devices(self) -> List[PCIDevice]:
        """Get PCI device information"""
        devices = []
        
        lspci_output = self.run_command(["lspci", "-v"])
        if not lspci_output:
            return devices
        
        current_device = None
        for line in lspci_output.split('\n'):
            if line and not line.startswith('\t'):
                # New device
                if current_device:
                    devices.append(current_device)
                
                parts = line.split(' ', 2)
                if len(parts) >= 3:
                    slot = parts[0]
                    device_class = parts[1].rstrip(':')
                    description = parts[2]
                    
                    # Parse vendor and device from description
                    vendor = "unknown"
                    device = "unknown"
                    if ':' in description:
                        vendor_device = description.split(':', 1)
                        vendor = vendor_device[0].strip()
                        device = vendor_device[1].strip() if len(vendor_device) > 1 else "unknown"
                    
                    current_device = PCIDevice(
                        slot=slot,
                        device_class=device_class,
                        vendor=vendor,
                        device=device,
                        driver=None
                    )
            elif line.startswith('\t') and current_device:
                # Device details
                if 'Kernel driver in use:' in line:
                    current_device.driver = line.split(':', 1)[1].strip()
        
        if current_device:
            devices.append(current_device)
        
        return devices
    
    def get_bmc_info(self) -> BMCInfo:
        """Get BMC/IPMI information"""
        present = False
        version = None
        manufacturer = None
        ip_address = None
        mac_address = None
        
        # Check if IPMI is available
        ipmitool_output = self.run_command(["ipmitool", "mc", "info"])
        if ipmitool_output:
            present = True
            for line in ipmitool_output.split('\n'):
                if 'Firmware Revision' in line:
                    version = line.split(':', 1)[1].strip()
                elif 'Manufacturer Name' in line:
                    manufacturer = line.split(':', 1)[1].strip()
        
        # Get BMC network info
        if present:
            lan_output = self.run_command(["ipmitool", "lan", "print"])
            if lan_output:
                for line in lan_output.split('\n'):
                    if 'IP Address' in line and 'Source' not in line:
                        ip_address = line.split(':', 1)[1].strip()
                    elif 'MAC Address' in line:
                        mac_address = line.split(':', 1)[1].strip()
        
        return BMCInfo(
            present=present,
            version=version,
            manufacturer=manufacturer,
            ip_address=ip_address,
            mac_address=mac_address
        )
    
    def get_firmware_info(self) -> Dict[str, Any]:
        """Get firmware information"""
        firmware = {}
        
        # BIOS/UEFI information from dmidecode
        dmidecode_output = self.run_command(["dmidecode", "-t", "bios"])
        if dmidecode_output:
            bios_info = {}
            for line in dmidecode_output.split('\n'):
                line = line.strip()
                if ':' in line and not line.startswith('Handle'):
                    key, value = line.split(':', 1)
                    bios_info[key.strip()] = value.strip()
            firmware['bios'] = bios_info
        
        # System information
        system_output = self.run_command(["dmidecode", "-t", "system"])
        if system_output:
            system_info = {}
            for line in system_output.split('\n'):
                line = line.strip()
                if ':' in line and not line.startswith('Handle'):
                    key, value = line.split(':', 1)
                    system_info[key.strip()] = value.strip()
            firmware['system'] = system_info
        
        return firmware
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string to bytes"""
        if not size_str:
            return 0
        
        size_str = size_str.upper().replace(' ', '')
        multipliers = {
            'B': 1,
            'KB': 1024,
            'MB': 1024**2,
            'GB': 1024**3,
            'TB': 1024**4,
            'K': 1024,
            'M': 1024**2,
            'G': 1024**3,
            'T': 1024**4
        }
        
        for suffix, multiplier in multipliers.items():
            if size_str.endswith(suffix):
                try:
                    return int(float(size_str[:-len(suffix)]) * multiplier)
                except ValueError:
                    return 0
        
        try:
            return int(size_str)
        except ValueError:
            return 0
    
    def enumerate_hardware(self) -> HardwareInventory:
        """Perform complete hardware enumeration"""
        self.logger.info("Starting hardware enumeration")
        
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        
        system = self.get_system_info()
        cpu = self.get_cpu_info()
        memory = self.get_memory_info()
        storage = self.get_storage_info()
        network = self.get_network_interfaces()
        pci_devices = self.get_pci_devices()
        bmc = self.get_bmc_info()
        firmware = self.get_firmware_info()
        
        inventory = HardwareInventory(
            timestamp=timestamp,
            system=system,
            cpu=cpu,
            memory=memory,
            storage=storage,
            network=network,
            pci_devices=pci_devices,
            bmc=bmc,
            firmware=firmware
        )
        
        self.logger.info("Hardware enumeration completed", 
                        network_interfaces=len(network),
                        storage_devices=len(storage),
                        pci_devices=len(pci_devices))
        
        return inventory

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Hardware Inventory Tool")
    parser.add_argument("--output", "-o", 
                       help="Output file path")
    parser.add_argument("--pretty", action="store_true",
                       help="Pretty print JSON output")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    enumerator = HardwareEnumerator()
    
    try:
        inventory = enumerator.enumerate_hardware()
        
        # Convert to dict for JSON serialization
        inventory_dict = asdict(inventory)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(inventory_dict, f, indent=2 if args.pretty else None)
            print(f"Hardware inventory saved to: {args.output}")
        else:
            print(json.dumps(inventory_dict, indent=2 if args.pretty else None))
        
        return 0
        
    except Exception as e:
        logger.error("Hardware enumeration failed", error=str(e))
        return 1

if __name__ == "__main__":
    sys.exit(main())
