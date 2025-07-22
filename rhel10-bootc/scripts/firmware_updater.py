#!/usr/bin/env python3
"""
Garden-Tiller Firmware Update Script
Automated firmware updates for BIOS, BMC, network cards, and storage devices
"""

import json
import subprocess
import sys
import time
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
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
class FirmwareComponent:
    """Firmware component information"""
    component_type: str
    name: str
    current_version: str
    vendor: str
    device_id: Optional[str]
    updateable: bool
    critical: bool

@dataclass
class FirmwareUpdate:
    """Firmware update information"""
    component: FirmwareComponent
    available_version: Optional[str]
    update_needed: bool
    security_update: bool
    update_method: str
    update_file: Optional[str]

@dataclass
class UpdateResult:
    """Firmware update result"""
    component: FirmwareComponent
    success: bool
    previous_version: str
    new_version: Optional[str]
    error: Optional[str]
    reboot_required: bool
    update_time: float

@dataclass
class FirmwareInventory:
    """Complete firmware inventory and update status"""
    timestamp: str
    hostname: str
    components: List[FirmwareComponent]
    available_updates: List[FirmwareUpdate]
    update_results: List[UpdateResult]
    security_recommendations: List[str]

class FirmwareUpdater:
    """Firmware update management class"""
    
    def __init__(self, firmware_path: Optional[str] = None, auto_update: bool = False):
        self.logger = structlog.get_logger(self.__class__.__name__)
        self.firmware_path = Path(firmware_path) if firmware_path else Path("/opt/firmware")
        self.auto_update = auto_update
        self.supported_vendors = ["dell", "hp", "lenovo", "supermicro", "intel", "broadcom"]
        
    def run_command(self, cmd: List[str], ignore_errors: bool = True, timeout: int = 300) -> Optional[str]:
        """Run a system command and return output"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=timeout)
            return result.stdout.strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            if not ignore_errors:
                self.logger.error("Command failed", cmd=" ".join(cmd), error=str(e))
            return None
        except FileNotFoundError:
            if not ignore_errors:
                self.logger.error("Command not found", cmd=" ".join(cmd))
            return None
    
    def detect_firmware_components(self) -> List[FirmwareComponent]:
        """Detect all firmware components in the system"""
        self.logger.info("Detecting firmware components")
        components = []
        
        # BIOS/UEFI firmware
        bios_info = self._get_bios_info()
        if bios_info:
            components.append(bios_info)
        
        # BMC firmware
        bmc_info = self._get_bmc_info()
        if bmc_info:
            components.append(bmc_info)
        
        # Network card firmware
        network_components = self._get_network_firmware()
        components.extend(network_components)
        
        # Storage device firmware
        storage_components = self._get_storage_firmware()
        components.extend(storage_components)
        
        # GPU firmware (if present)
        gpu_components = self._get_gpu_firmware()
        components.extend(gpu_components)
        
        self.logger.info("Firmware component detection completed", count=len(components))
        return components
    
    def _get_bios_info(self) -> Optional[FirmwareComponent]:
        """Get BIOS/UEFI firmware information"""
        dmidecode_output = self.run_command(["dmidecode", "-t", "bios"])
        if not dmidecode_output:
            return None
        
        vendor = "unknown"
        version = "unknown"
        
        for line in dmidecode_output.split('\n'):
            line = line.strip()
            if line.startswith('Vendor:'):
                vendor = line.split(':', 1)[1].strip()
            elif line.startswith('Version:'):
                version = line.split(':', 1)[1].strip()
        
        return FirmwareComponent(
            component_type="bios",
            name="System BIOS/UEFI",
            current_version=version,
            vendor=vendor,
            device_id=None,
            updateable=True,
            critical=True
        )
    
    def _get_bmc_info(self) -> Optional[FirmwareComponent]:
        """Get BMC firmware information"""
        ipmitool_output = self.run_command(["ipmitool", "mc", "info"])
        if not ipmitool_output:
            return None
        
        vendor = "unknown"
        version = "unknown"
        
        for line in ipmitool_output.split('\n'):
            if 'Manufacturer Name' in line:
                vendor = line.split(':', 1)[1].strip()
            elif 'Firmware Revision' in line:
                version = line.split(':', 1)[1].strip()
        
        return FirmwareComponent(
            component_type="bmc",
            name="Baseboard Management Controller",
            current_version=version,
            vendor=vendor,
            device_id=None,
            updateable=True,
            critical=True
        )
    
    def _get_network_firmware(self) -> List[FirmwareComponent]:
        """Get network card firmware information"""
        components = []
        
        # Get PCI network devices
        lspci_output = self.run_command(["lspci", "-v", "-d", "*:*"])
        if not lspci_output:
            return components
        
        current_device = {}
        for line in lspci_output.split('\n'):
            if line and not line.startswith('\t'):
                # Process previous device
                if current_device and 'network' in current_device.get('class', '').lower():
                    components.append(self._create_network_component(current_device))
                
                # Start new device
                parts = line.split(' ', 2)
                if len(parts) >= 3:
                    current_device = {
                        'pci_id': parts[0],
                        'class': parts[1],
                        'description': parts[2]
                    }
            elif line.startswith('\t') and current_device:
                # Device details
                if 'Subsystem:' in line:
                    current_device['subsystem'] = line.split(':', 1)[1].strip()
                elif 'Kernel driver in use:' in line:
                    current_device['driver'] = line.split(':', 1)[1].strip()
        
        # Process last device
        if current_device and 'network' in current_device.get('class', '').lower():
            components.append(self._create_network_component(current_device))
        
        return components
    
    def _create_network_component(self, device_info: Dict[str, str]) -> FirmwareComponent:
        """Create network component from device info"""
        # Try to get firmware version via ethtool
        driver = device_info.get('driver', '')
        version = "unknown"
        
        if driver:
            # Find interface using this driver
            ip_output = self.run_command(["ip", "link", "show"])
            if ip_output:
                for line in ip_output.split('\n'):
                    if ': <' in line and 'lo:' not in line:
                        iface_name = line.split(':', 2)[1].strip()
                        ethtool_output = self.run_command(["ethtool", "-i", iface_name])
                        if ethtool_output and f"driver: {driver}" in ethtool_output:
                            for ethtool_line in ethtool_output.split('\n'):
                                if ethtool_line.startswith('firmware-version:'):
                                    version = ethtool_line.split(':', 1)[1].strip()
                                    break
                            break
        
        # Extract vendor from description
        vendor = "unknown"
        description = device_info.get('description', '')
        for known_vendor in ['Intel', 'Broadcom', 'Realtek', 'Mellanox', 'Chelsio']:
            if known_vendor.lower() in description.lower():
                vendor = known_vendor
                break
        
        return FirmwareComponent(
            component_type="network",
            name=f"Network Controller ({description})",
            current_version=version,
            vendor=vendor,
            device_id=device_info.get('pci_id'),
            updateable=True,
            critical=False
        )
    
    def _get_storage_firmware(self) -> List[FirmwareComponent]:
        """Get storage device firmware information"""
        components = []
        
        # NVMe devices
        nvme_output = self.run_command(["nvme", "list"])
        if nvme_output:
            for line in nvme_output.split('\n')[2:]:  # Skip header
                if line.strip() and '/dev/nvme' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        device = parts[0]
                        model = parts[1] if len(parts) > 1 else "unknown"
                        
                        # Get firmware version
                        firmware_version = "unknown"
                        id_output = self.run_command(["nvme", "id-ctrl", device])
                        if id_output:
                            for id_line in id_output.split('\n'):
                                if 'fr ' in id_line:
                                    firmware_version = id_line.split(':', 1)[1].strip()
                                    break
                        
                        components.append(FirmwareComponent(
                            component_type="storage",
                            name=f"NVMe SSD ({model})",
                            current_version=firmware_version,
                            vendor=self._extract_vendor_from_model(model),
                            device_id=device,
                            updateable=True,
                            critical=False
                        ))
        
        # SATA/SAS devices via smartctl
        lsblk_output = self.run_command(["lsblk", "-d", "-o", "NAME,TYPE"])
        if lsblk_output:
            for line in lsblk_output.split('\n')[1:]:  # Skip header
                if 'disk' in line:
                    device_name = line.split()[0]
                    device_path = f"/dev/{device_name}"
                    
                    if not device_name.startswith('nvme'):  # Skip NVMe, already handled
                        smart_output = self.run_command(["smartctl", "-i", device_path])
                        if smart_output:
                            model = "unknown"
                            firmware_version = "unknown"
                            
                            for smart_line in smart_output.split('\n'):
                                if smart_line.startswith('Device Model:'):
                                    model = smart_line.split(':', 1)[1].strip()
                                elif smart_line.startswith('Firmware Version:'):
                                    firmware_version = smart_line.split(':', 1)[1].strip()
                            
                            components.append(FirmwareComponent(
                                component_type="storage",
                                name=f"Storage Device ({model})",
                                current_version=firmware_version,
                                vendor=self._extract_vendor_from_model(model),
                                device_id=device_path,
                                updateable=True,
                                critical=False
                            ))
        
        return components
    
    def _get_gpu_firmware(self) -> List[FirmwareComponent]:
        """Get GPU firmware information"""
        components = []
        
        # NVIDIA GPUs
        nvidia_output = self.run_command(["nvidia-smi", "-q"])
        if nvidia_output:
            current_gpu = {}
            for line in nvidia_output.split('\n'):
                if 'Product Name' in line:
                    current_gpu['name'] = line.split(':', 1)[1].strip()
                elif 'VBIOS Version' in line:
                    current_gpu['firmware'] = line.split(':', 1)[1].strip()
                elif line.strip() == '' and current_gpu:
                    components.append(FirmwareComponent(
                        component_type="gpu",
                        name=f"NVIDIA GPU ({current_gpu.get('name', 'unknown')})",
                        current_version=current_gpu.get('firmware', 'unknown'),
                        vendor="NVIDIA",
                        device_id=None,
                        updateable=True,
                        critical=False
                    ))
                    current_gpu = {}
        
        return components
    
    def _extract_vendor_from_model(self, model: str) -> str:
        """Extract vendor name from device model string"""
        model_lower = model.lower()
        vendors = {
            'samsung': 'Samsung',
            'intel': 'Intel',
            'wd': 'Western Digital',
            'seagate': 'Seagate',
            'toshiba': 'Toshiba',
            'crucial': 'Crucial',
            'micron': 'Micron',
            'sandisk': 'SanDisk',
            'kingston': 'Kingston'
        }
        
        for vendor_key, vendor_name in vendors.items():
            if vendor_key in model_lower:
                return vendor_name
        
        return "unknown"
    
    def check_for_updates(self, components: List[FirmwareComponent]) -> List[FirmwareUpdate]:
        """Check for available firmware updates"""
        self.logger.info("Checking for firmware updates")
        updates = []
        
        for component in components:
            update_info = self._check_component_update(component)
            if update_info:
                updates.append(update_info)
        
        self.logger.info("Update check completed", available_updates=len([u for u in updates if u.update_needed]))
        return updates
    
    def _check_component_update(self, component: FirmwareComponent) -> Optional[FirmwareUpdate]:
        """Check for updates for a specific component"""
        
        # Use fwupd if available
        fwupd_output = self.run_command(["fwupdmgr", "get-devices"])
        if fwupd_output:
            return self._check_fwupd_update(component)
        
        # Vendor-specific update checks
        if component.vendor.lower() == "dell":
            return self._check_dell_update(component)
        elif component.vendor.lower() in ["hp", "hewlett-packard"]:
            return self._check_hp_update(component)
        elif component.vendor.lower() == "lenovo":
            return self._check_lenovo_update(component)
        
        # Generic update check
        return FirmwareUpdate(
            component=component,
            available_version=None,
            update_needed=False,
            security_update=False,
            update_method="manual",
            update_file=None
        )
    
    def _check_fwupd_update(self, component: FirmwareComponent) -> Optional[FirmwareUpdate]:
        """Check for updates using fwupd"""
        # Get device list from fwupd
        devices_output = self.run_command(["fwupdmgr", "get-devices", "--json"])
        if not devices_output:
            return None
        
        try:
            devices = json.loads(devices_output)
            for device in devices.get('Devices', []):
                if self._component_matches_fwupd_device(component, device):
                    # Check for updates
                    updates_output = self.run_command(["fwupdmgr", "get-updates", "--json", device.get('DeviceId', '')])
                    if updates_output:
                        updates = json.loads(updates_output)
                        if updates.get('Releases'):
                            latest_release = updates['Releases'][0]
                            return FirmwareUpdate(
                                component=component,
                                available_version=latest_release.get('Version'),
                                update_needed=True,
                                security_update='security' in latest_release.get('Categories', []),
                                update_method="fwupd",
                                update_file=None
                            )
        except json.JSONDecodeError:
            pass
        
        return None
    
    def _component_matches_fwupd_device(self, component: FirmwareComponent, fwupd_device: Dict[str, Any]) -> bool:
        """Check if component matches fwupd device"""
        device_name = fwupd_device.get('Name', '').lower()
        component_name = component.name.lower()
        
        # Simple name matching
        if component.component_type == "bios" and "bios" in device_name:
            return True
        elif component.component_type == "network" and "network" in device_name:
            return True
        elif component.component_type == "storage" and any(term in device_name for term in ["ssd", "nvme", "storage"]):
            return True
        
        return False
    
    def _check_dell_update(self, component: FirmwareComponent) -> Optional[FirmwareUpdate]:
        """Check for Dell-specific updates"""
        # Dell Update Package (DUP) check would go here
        # This is a placeholder for Dell-specific update logic
        return FirmwareUpdate(
            component=component,
            available_version=None,
            update_needed=False,
            security_update=False,
            update_method="dell_dup",
            update_file=None
        )
    
    def _check_hp_update(self, component: FirmwareComponent) -> Optional[FirmwareUpdate]:
        """Check for HP-specific updates"""
        # HP Smart Update Manager check would go here
        return FirmwareUpdate(
            component=component,
            available_version=None,
            update_needed=False,
            security_update=False,
            update_method="hp_sum",
            update_file=None
        )
    
    def _check_lenovo_update(self, component: FirmwareComponent) -> Optional[FirmwareUpdate]:
        """Check for Lenovo-specific updates"""
        # Lenovo System Update check would go here
        return FirmwareUpdate(
            component=component,
            available_version=None,
            update_needed=False,
            security_update=False,
            update_method="lenovo_tsu",
            update_file=None
        )
    
    def apply_updates(self, updates: List[FirmwareUpdate]) -> List[UpdateResult]:
        """Apply firmware updates"""
        self.logger.info("Applying firmware updates", count=len([u for u in updates if u.update_needed]))
        results = []
        
        for update in updates:
            if update.update_needed and (self.auto_update or update.security_update):
                result = self._apply_single_update(update)
                results.append(result)
        
        return results
    
    def _apply_single_update(self, update: FirmwareUpdate) -> UpdateResult:
        """Apply a single firmware update"""
        component = update.component
        start_time = time.time()
        
        self.logger.info("Applying firmware update", 
                        component=component.name, 
                        method=update.update_method)
        
        try:
            if update.update_method == "fwupd":
                return self._apply_fwupd_update(update, start_time)
            elif update.update_method == "dell_dup":
                return self._apply_dell_update(update, start_time)
            elif update.update_method == "hp_sum":
                return self._apply_hp_update(update, start_time)
            else:
                return UpdateResult(
                    component=component,
                    success=False,
                    previous_version=component.current_version,
                    new_version=None,
                    error="Unsupported update method",
                    reboot_required=False,
                    update_time=time.time() - start_time
                )
        
        except Exception as e:
            return UpdateResult(
                component=component,
                success=False,
                previous_version=component.current_version,
                new_version=None,
                error=str(e),
                reboot_required=False,
                update_time=time.time() - start_time
            )
    
    def _apply_fwupd_update(self, update: FirmwareUpdate, start_time: float) -> UpdateResult:
        """Apply update using fwupd"""
        component = update.component
        
        # Find the device ID
        devices_output = self.run_command(["fwupdmgr", "get-devices", "--json"])
        if not devices_output:
            raise Exception("Failed to get fwupd devices")
        
        devices = json.loads(devices_output)
        device_id = None
        
        for device in devices.get('Devices', []):
            if self._component_matches_fwupd_device(component, device):
                device_id = device.get('DeviceId')
                break
        
        if not device_id:
            raise Exception("Device not found in fwupd")
        
        # Apply update
        update_output = self.run_command(["fwupdmgr", "update", device_id, "--assume-yes"], ignore_errors=False)
        
        # Check if update was successful
        success = update_output is not None and "successfully" in update_output.lower()
        
        return UpdateResult(
            component=component,
            success=success,
            previous_version=component.current_version,
            new_version=update.available_version if success else None,
            error=None if success else "Update failed",
            reboot_required=component.component_type in ["bios", "bmc"],
            update_time=time.time() - start_time
        )
    
    def _apply_dell_update(self, update: FirmwareUpdate, start_time: float) -> UpdateResult:
        """Apply Dell-specific update"""
        # Placeholder for Dell update logic
        return UpdateResult(
            component=update.component,
            success=False,
            previous_version=update.component.current_version,
            new_version=None,
            error="Dell updates not implemented",
            reboot_required=False,
            update_time=time.time() - start_time
        )
    
    def _apply_hp_update(self, update: FirmwareUpdate, start_time: float) -> UpdateResult:
        """Apply HP-specific update"""
        # Placeholder for HP update logic
        return UpdateResult(
            component=update.component,
            success=False,
            previous_version=update.component.current_version,
            new_version=None,
            error="HP updates not implemented",
            reboot_required=False,
            update_time=time.time() - start_time
        )
    
    def generate_security_recommendations(self, components: List[FirmwareComponent], 
                                        updates: List[FirmwareUpdate]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Check for critical components with outdated firmware
        critical_components = [c for c in components if c.critical]
        outdated_critical = [u for u in updates if u.component.critical and u.update_needed]
        
        if outdated_critical:
            recommendations.append(f"Critical security updates available for {len(outdated_critical)} components")
        
        # Check for security updates
        security_updates = [u for u in updates if u.security_update]
        if security_updates:
            recommendations.append(f"Security updates available for: {', '.join([u.component.name for u in security_updates])}")
        
        # Check for BIOS/BMC updates
        bios_updates = [u for u in updates if u.component.component_type == "bios" and u.update_needed]
        bmc_updates = [u for u in updates if u.component.component_type == "bmc" and u.update_needed]
        
        if bios_updates:
            recommendations.append("BIOS update available - consider updating during maintenance window")
        if bmc_updates:
            recommendations.append("BMC update available - critical for remote management security")
        
        return recommendations
    
    def get_firmware_inventory(self) -> FirmwareInventory:
        """Get complete firmware inventory and update status"""
        self.logger.info("Getting firmware inventory")
        
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        hostname = self.run_command(["hostname"]) or "unknown"
        
        # Detect components
        components = self.detect_firmware_components()
        
        # Check for updates
        available_updates = self.check_for_updates(components)
        
        # Apply updates if auto-update is enabled
        update_results = []
        if self.auto_update:
            update_results = self.apply_updates(available_updates)
        
        # Generate recommendations
        security_recommendations = self.generate_security_recommendations(components, available_updates)
        
        inventory = FirmwareInventory(
            timestamp=timestamp,
            hostname=hostname,
            components=components,
            available_updates=available_updates,
            update_results=update_results,
            security_recommendations=security_recommendations
        )
        
        self.logger.info("Firmware inventory completed", 
                        components=len(components),
                        available_updates=len([u for u in available_updates if u.update_needed]),
                        security_updates=len([u for u in available_updates if u.security_update]))
        
        return inventory

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--output", "-o", 
                       help="Output file path")
    parser.add_argument("--firmware-path", 
                       help="Path to firmware files")
    parser.add_argument("--auto-update", action="store_true",
                       help="Automatically apply firmware updates")
    parser.add_argument("--check-only", action="store_true",
                       help="Only check for updates, don't apply")
    parser.add_argument("--pretty", action="store_true",
                       help="Pretty print JSON output")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    updater = FirmwareUpdater(
        firmware_path=args.firmware_path,
        auto_update=args.auto_update and not args.check_only
    )
    
    try:
        inventory = updater.get_firmware_inventory()
        
        # Convert to dict for JSON serialization
        inventory_dict = asdict(inventory)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(inventory_dict, f, indent=2 if args.pretty else None)
            print(f"Firmware inventory saved to: {args.output}")
        else:
            print(json.dumps(inventory_dict, indent=2 if args.pretty else None))
        
        # Print summary
        updates_needed = len([u for u in inventory.available_updates if u.update_needed])
        security_updates = len([u for u in inventory.available_updates if u.security_update])
        
        print(f"Firmware Summary:")
        print(f"  Components detected: {len(inventory.components)}")
        print(f"  Updates available: {updates_needed}")
        print(f"  Security updates: {security_updates}")
        
        if inventory.security_recommendations:
            print("Security Recommendations:")
            for rec in inventory.security_recommendations:
                print(f"  - {rec}")
        
        return 0
        
    except Exception as e:
        logger.error("Firmware update failed", error=str(e))
        return 1

if __name__ == "__main__":
    sys.exit(main())
