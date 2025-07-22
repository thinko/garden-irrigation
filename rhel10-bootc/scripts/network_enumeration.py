#!/usr/bin/env python3
"""
Garden-Tiller Network Enumeration and Testing Script
Comprehensive network interface enumeration, LACP testing, and connectivity validation
"""

import json
import subprocess
import sys
import time
import logging
import argparse
import socket
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
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
class NetworkInterface:
    """Network interface information"""
    name: str
    mac_address: str
    driver: str
    speed: Optional[str]
    duplex: Optional[str]
    state: str
    mtu: int
    pci_id: Optional[str]
    supports_bonding: bool
    vlan_capable: bool

@dataclass
class BondingTest:
    """Bonding test result"""
    mode: str
    interfaces: List[str]
    negotiation_time: float
    success: bool
    error: Optional[str]
    link_status: Dict[str, str]

@dataclass
class VLANTest:
    """VLAN test result"""
    vlan_id: int
    interface: str
    success: bool
    ip_assigned: Optional[str]
    error: Optional[str]

@dataclass
class ConnectivityTest:
    """Network connectivity test result"""
    target: str
    method: str
    success: bool
    latency: Optional[float]
    error: Optional[str]

@dataclass
class NetworkTopology:
    """Network topology information"""
    switches: List[Dict[str, Any]]
    vlans_discovered: List[int]
    subnets_discovered: List[str]
    gateways: List[str]
    dns_servers: List[str]

@dataclass
class NetworkEnumeration:
    """Complete network enumeration results"""
    timestamp: str
    hostname: str
    interfaces: List[NetworkInterface]
    bonding_tests: List[BondingTest]
    vlan_tests: List[VLANTest]
    connectivity_tests: List[ConnectivityTest]
    topology: NetworkTopology
    configuration_recommendations: List[str]

class NetworkEnumerator:
    """Network enumeration and testing class"""
    
    def __init__(self, controller_ip: Optional[str] = None, test_vlans: Optional[List[int]] = None, test_subnets: Optional[List[str]] = None):
        self.logger = structlog.get_logger(self.__class__.__name__)
        self.controller_ip = controller_ip
        self.test_vlans = test_vlans or [10, 20, 30, 100, 200]
        self.test_subnets = test_subnets or ["10.9.1.0/24", "10.9.2.0/24", "192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"]
        self.bonding_modes = ["802.3ad", "active-backup", "balance-xor", "broadcast"]
        
    def run_command(self, cmd: List[str], ignore_errors: bool = True, timeout: int = 30) -> Optional[str]:
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
    
    def get_network_interfaces(self) -> List[NetworkInterface]:
        """Get detailed network interface information"""
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
                    
                    # Get interface state and MTU
                    state = "DOWN"
                    mtu = 1500
                    
                    if "state UP" in line:
                        state = "UP"
                    elif "state DOWN" in line:
                        state = "DOWN"
                    
                    if "mtu" in line:
                        try:
                            mtu_part = line.split("mtu")[1].split()[0]
                            mtu = int(mtu_part)
                        except (IndexError, ValueError):
                            pass
                    
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
                    
                    # Check bonding and VLAN capabilities
                    supports_bonding = self._check_bonding_support(iface_name)
                    vlan_capable = self._check_vlan_support(iface_name)
                    
                    interfaces.append(NetworkInterface(
                        name=iface_name,
                        mac_address=mac_addr,
                        driver=driver,
                        speed=speed,
                        duplex=duplex,
                        state=state,
                        mtu=mtu,
                        pci_id=pci_id,
                        supports_bonding=supports_bonding,
                        vlan_capable=vlan_capable
                    ))
        
        return interfaces
    
    def _check_bonding_support(self, interface: str) -> bool:
        """Check if interface supports bonding"""
        # Check if interface can be enslaved
        try:
            with open(f"/sys/class/net/{interface}/flags", "r") as f:
                flags = int(f.read().strip(), 16)
                # Check if IFF_SLAVE bit is available (this is a simplified check)
                return True
        except:
            return False
    
    def _check_vlan_support(self, interface: str) -> bool:
        """Check if interface supports VLAN tagging"""
        ethtool_output = self.run_command(["ethtool", "-k", interface])
        if ethtool_output and "rx-vlan-offload: on" in ethtool_output:
            return True
        return True  # Most modern interfaces support VLANs
    
    def test_bonding_configuration(self, interfaces: List[NetworkInterface]) -> List[BondingTest]:
        """Test different bonding configurations"""
        self.logger.info("Testing bonding configurations")
        bonding_tests = []
        
        # Filter interfaces that support bonding
        bondable_interfaces = [iface for iface in interfaces if iface.supports_bonding and iface.state == "UP"]
        
        if len(bondable_interfaces) < 2:
            self.logger.warning("Not enough interfaces for bonding tests")
            return bonding_tests
        
        # Test different combinations
        for mode in self.bonding_modes:
            for i in range(2, min(5, len(bondable_interfaces) + 1)):  # Test 2-4 interfaces
                test_interfaces = bondable_interfaces[:i]
                test_result = self._test_bond_configuration(mode, test_interfaces)
                bonding_tests.append(test_result)
        
        return bonding_tests
    
    def _test_bond_configuration(self, mode: str, interfaces: List[NetworkInterface]) -> BondingTest:
        """Test a specific bonding configuration"""
        interface_names = [iface.name for iface in interfaces]
        self.logger.info("Testing bond configuration", mode=mode, interfaces=interface_names)
        
        bond_name = f"bond_test_{int(time.time())}"
        start_time = time.time()
        
        try:
            # Create bond interface
            self.run_command(["modprobe", "bonding"], ignore_errors=False)
            self.run_command(["ip", "link", "add", bond_name, "type", "bond", "mode", mode], ignore_errors=False)
            
            # Add interfaces to bond
            for iface in interface_names:
                self.run_command(["ip", "link", "set", iface, "master", bond_name], ignore_errors=False)
            
            # Bring up bond
            self.run_command(["ip", "link", "set", bond_name, "up"], ignore_errors=False)
            
            # Wait for negotiation
            negotiation_time = 0
            max_wait = 30
            link_status = {}
            
            while negotiation_time < max_wait:
                time.sleep(1)
                negotiation_time += 1
                
                # Check bond status
                bond_status = self.run_command(["cat", f"/proc/net/bonding/{bond_name}"])
                if bond_status:
                    # Parse link status
                    for iface in interface_names:
                        if f"Slave Interface: {iface}" in bond_status:
                            # Extract link status for this interface
                            link_status[iface] = "up" if "Link Status: up" in bond_status else "down"
                    
                    # Check if all links are up
                    if all(status == "up" for status in link_status.values()):
                        break
            
            negotiation_time = time.time() - start_time
            success = len(link_status) > 0 and all(status == "up" for status in link_status.values())
            
            return BondingTest(
                mode=mode,
                interfaces=interface_names,
                negotiation_time=negotiation_time,
                success=success,
                error=None,
                link_status=link_status
            )
            
        except Exception as e:
            return BondingTest(
                mode=mode,
                interfaces=interface_names,
                negotiation_time=time.time() - start_time,
                success=False,
                error=str(e),
                link_status={}
            )
        finally:
            # Cleanup
            try:
                for iface in interface_names:
                    self.run_command(["ip", "link", "set", iface, "nomaster"])
                self.run_command(["ip", "link", "del", bond_name])
            except:
                pass
    
    def test_vlan_configurations(self, interfaces: List[NetworkInterface]) -> List[VLANTest]:
        """Test VLAN configurations"""
        self.logger.info("Testing VLAN configurations")
        vlan_tests = []
        
        # Test VLANs on each capable interface
        for interface in interfaces:
            if interface.vlan_capable and interface.state == "UP":
                for vlan_id in self.test_vlans:
                    test_result = self._test_vlan_configuration(interface.name, vlan_id)
                    vlan_tests.append(test_result)
        
        return vlan_tests
    
    def _test_vlan_configuration(self, interface: str, vlan_id: int) -> VLANTest:
        """Test a specific VLAN configuration"""
        self.logger.info("Testing VLAN configuration", interface=interface, vlan_id=vlan_id)
        
        vlan_interface = f"{interface}.{vlan_id}"
        
        try:
            # Create VLAN interface
            self.run_command(["ip", "link", "add", "link", interface, "name", vlan_interface, "type", "vlan", "id", str(vlan_id)], ignore_errors=False)
            
            # Bring up VLAN interface
            self.run_command(["ip", "link", "set", vlan_interface, "up"], ignore_errors=False)
            
            # Try to get IP via DHCP (with timeout)
            ip_assigned = None
            dhcp_result = self.run_command(["timeout", "10", "dhclient", "-1", vlan_interface])
            
            # Check if IP was assigned
            ip_output = self.run_command(["ip", "addr", "show", vlan_interface])
            if ip_output and "inet " in ip_output:
                # Extract IP address
                for line in ip_output.split('\n'):
                    if "inet " in line:
                        ip_assigned = line.split("inet ")[1].split("/")[0]
                        break
            
            return VLANTest(
                vlan_id=vlan_id,
                interface=interface,
                success=ip_assigned is not None,
                ip_assigned=ip_assigned,
                error=None
            )
            
        except Exception as e:
            return VLANTest(
                vlan_id=vlan_id,
                interface=interface,
                success=False,
                ip_assigned=None,
                error=str(e)
            )
        finally:
            # Cleanup
            try:
                self.run_command(["ip", "link", "del", vlan_interface])
            except:
                pass
    
    def test_connectivity(self) -> List[ConnectivityTest]:
        """Test network connectivity"""
        self.logger.info("Testing network connectivity")
        tests = []
        
        # Test targets
        targets = [
            ("8.8.8.8", "ping"),
            ("1.1.1.1", "ping"),
            ("google.com", "dns"),
            ("github.com", "https")
        ]
        
        if self.controller_ip:
            targets.append((self.controller_ip, "ping"))
            targets.append((self.controller_ip, "tcp_8080"))
        
        for target, method in targets:
            test_result = self._test_connectivity(target, method)
            tests.append(test_result)
        
        return tests
    
    def _test_connectivity(self, target: str, method: str) -> ConnectivityTest:
        """Test connectivity to a specific target"""
        start_time = time.time()
        
        try:
            if method == "ping":
                result = self.run_command(["ping", "-c", "3", "-W", "5", target], ignore_errors=False)
                if result and "3 received" in result:
                    # Extract average latency
                    latency = None
                    for line in result.split('\n'):
                        if "rtt min/avg/max/mdev" in line:
                            avg_latency = line.split('/')[5]
                            latency = float(avg_latency)
                            break
                    
                    return ConnectivityTest(
                        target=target,
                        method=method,
                        success=True,
                        latency=latency,
                        error=None
                    )
                else:
                    return ConnectivityTest(
                        target=target,
                        method=method,
                        success=False,
                        latency=None,
                        error="No ping response"
                    )
            
            elif method == "dns":
                result = self.run_command(["nslookup", target], ignore_errors=False)
                success = result is not None and "Name:" in result
                
                return ConnectivityTest(
                    target=target,
                    method=method,
                    success=success,
                    latency=time.time() - start_time,
                    error=None if success else "DNS resolution failed"
                )
            
            elif method == "https":
                result = self.run_command(["curl", "-I", "-s", "-w", "%{http_code}", f"https://{target}", "--max-time", "10"], ignore_errors=False)
                success = result is not None and ("200" in result or "301" in result or "302" in result)
                
                return ConnectivityTest(
                    target=target,
                    method=method,
                    success=success,
                    latency=time.time() - start_time,
                    error=None if success else f"HTTP error: {result}"
                )
            
            elif method.startswith("tcp_"):
                port = int(method.split("_")[1])
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((target, port))
                sock.close()
                
                success = result == 0
                return ConnectivityTest(
                    target=target,
                    method=method,
                    success=success,
                    latency=time.time() - start_time,
                    error=None if success else f"Connection refused on port {port}"
                )
            
            else:
                return ConnectivityTest(
                    target=target,
                    method=method,
                    success=False,
                    latency=time.time() - start_time,
                    error=f"Unknown test method: {method}"
                )
        
        except Exception as e:
            return ConnectivityTest(
                target=target,
                method=method,
                success=False,
                latency=time.time() - start_time,
                error=str(e)
            )
    
    def discover_network_topology(self) -> NetworkTopology:
        """Discover network topology"""
        self.logger.info("Discovering network topology")
        
        switches = []
        vlans_discovered = []
        subnets_discovered = []
        gateways = []
        dns_servers = []
        
        # Discover switches via LLDP
        lldp_output = self.run_command(["lldpctl"])
        if lldp_output:
            # Parse LLDP information
            current_switch = {}
            for line in lldp_output.split('\n'):
                if 'SysName:' in line:
                    current_switch['name'] = line.split(':', 1)[1].strip()
                elif 'SysDescr:' in line:
                    current_switch['description'] = line.split(':', 1)[1].strip()
                elif 'MgmtIP:' in line:
                    current_switch['management_ip'] = line.split(':', 1)[1].strip()
                elif line.strip() == '' and current_switch:
                    switches.append(current_switch)
                    current_switch = {}
        
        # Get routing information
        route_output = self.run_command(["ip", "route", "show"])
        if route_output:
            for line in route_output.split('\n'):
                if 'default via' in line:
                    gateway = line.split('default via')[1].split()[0]
                    gateways.append(gateway)
                elif '/' in line and 'scope link' in line:
                    # Extract subnet
                    parts = line.split()
                    if parts and '/' in parts[0]:
                        subnets_discovered.append(parts[0])
        
        # Get DNS servers
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns_servers.append(line.split()[1])
        except:
            pass
        
        return NetworkTopology(
            switches=switches,
            vlans_discovered=vlans_discovered,
            subnets_discovered=subnets_discovered,
            gateways=gateways,
            dns_servers=dns_servers
        )
    
    def generate_recommendations(self, interfaces: List[NetworkInterface], bonding_tests: List[BondingTest], 
                               vlan_tests: List[VLANTest], connectivity_tests: List[ConnectivityTest]) -> List[str]:
        """Generate configuration recommendations"""
        recommendations = []
        
        # Bonding recommendations
        successful_bonds = [test for test in bonding_tests if test.success]
        if successful_bonds:
            best_bond = min(successful_bonds, key=lambda x: x.negotiation_time)
            recommendations.append(f"Recommended bonding: {best_bond.mode} with {len(best_bond.interfaces)} interfaces")
        
        # VLAN recommendations
        working_vlans = [test for test in vlan_tests if test.success]
        if working_vlans:
            vlan_ids = [test.vlan_id for test in working_vlans]
            recommendations.append(f"Working VLANs detected: {', '.join(map(str, vlan_ids))}")
        
        # Connectivity recommendations
        failed_tests = [test for test in connectivity_tests if not test.success]
        if failed_tests:
            recommendations.append(f"Connectivity issues detected for: {', '.join([test.target for test in failed_tests])}")
        
        # Interface recommendations
        fast_interfaces = [iface for iface in interfaces if iface.speed and "1000" in iface.speed]
        if fast_interfaces:
            recommendations.append(f"High-speed interfaces available: {', '.join([iface.name for iface in fast_interfaces])}")
        
        return recommendations
    
    def enumerate_network(self) -> NetworkEnumeration:
        """Perform complete network enumeration"""
        self.logger.info("Starting network enumeration")
        
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        hostname = self.run_command(["hostname"]) or "unknown"
        
        # Enumerate interfaces
        interfaces = self.get_network_interfaces()
        
        # Test bonding configurations
        bonding_tests = self.test_bonding_configuration(interfaces)
        
        # Test VLAN configurations
        vlan_tests = self.test_vlan_configurations(interfaces)
        
        # Test connectivity
        connectivity_tests = self.test_connectivity()
        
        # Discover topology
        topology = self.discover_network_topology()
        
        # Generate recommendations
        recommendations = self.generate_recommendations(interfaces, bonding_tests, vlan_tests, connectivity_tests)
        
        enumeration = NetworkEnumeration(
            timestamp=timestamp,
            hostname=hostname,
            interfaces=interfaces,
            bonding_tests=bonding_tests,
            vlan_tests=vlan_tests,
            connectivity_tests=connectivity_tests,
            topology=topology,
            configuration_recommendations=recommendations
        )
        
        self.logger.info("Network enumeration completed", 
                        interfaces=len(interfaces),
                        bonding_tests=len(bonding_tests),
                        vlan_tests=len(vlan_tests),
                        connectivity_tests=len(connectivity_tests))
        
        return enumeration

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Network Enumeration and Testing Tool")
    parser.add_argument("--output", "-o", 
                       help="Output file path")
    parser.add_argument("--controller-ip", 
                       help="Controller IP address for reporting")
    parser.add_argument("--test-vlans", nargs="+", type=int,
                       help="VLAN IDs to test")
    parser.add_argument("--test-subnets", nargs="+",
                       help="Subnets to test")
    parser.add_argument("--pretty", action="store_true",
                       help="Pretty print JSON output")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    enumerator = NetworkEnumerator(
        controller_ip=args.controller_ip,
        test_vlans=args.test_vlans,
        test_subnets=args.test_subnets
    )
    
    try:
        enumeration = enumerator.enumerate_network()
        
        # Convert to dict for JSON serialization
        enumeration_dict = asdict(enumeration)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(enumeration_dict, f, indent=2 if args.pretty else None)
            print(f"Network enumeration saved to: {args.output}")
        else:
            print(json.dumps(enumeration_dict, indent=2 if args.pretty else None))
        
        return 0
        
    except Exception as e:
        logger.error("Network enumeration failed", error=str(e))
        return 1

if __name__ == "__main__":
    sys.exit(main())
