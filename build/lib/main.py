#!/usr/bin/env python3

import argparse
import ipaddress
import os
import socket
import subprocess
import sys
import time
from typing import Dict, Optional, Tuple
import platform

import netifaces
from scapy.all import ARP, Ether, srp, conf
from zeroconf import ServiceBrowser, Zeroconf, ServiceListener

# Enhanced MAC address prefixes
MAC_PREFIXES = {
    '90:32:4b': 'RouterBoard',
    '90:09:d0': 'Synology',
    'a8:8f:d9': 'Apple',
    'ae:c4:35': 'Apple',
    '48:5f:99': 'Google',
    'b2:6a:53': 'Apple',
    'ce:b5:f8': 'Apple',
    'ee:38:c5': 'Apple',
}

class MDNSListener(ServiceListener):
    def __init__(self):
        self.ip_to_info = {}
        self.errors = set()
        self.local_hostname = get_local_hostname()  # Store local hostname

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        try:
            info = zc.get_service_info(type_, name, timeout=1000)
            if info and info.addresses:
                for addr in info.addresses:
                    ip_addr = socket.inet_ntoa(addr)
                    if info.server:
                        # Clean up the server name
                        server_name = info.server.rstrip('.')
                        
                        # Store more metadata
                        self.ip_to_info[ip_addr] = {
                            'name': server_name,
                            'type': type_,
                            'properties': info.properties,
                            'is_local': server_name == self.local_hostname
                        }
                        print(f"Found mDNS service: {server_name} ({ip_addr}) - {type_}")
        except Exception as e:
            if str(e) not in self.errors:
                self.errors.add(str(e))
                print(f"mDNS discovery error: {e}")

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.add_service(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

def get_local_hostname() -> str:
    """Get the local hostname with .local suffix if not present"""
    hostname = socket.gethostname()
    if not hostname.endswith('.local'):
        hostname += '.local'
    return hostname.lower()  # Normalize to lowercase

def identify_local_interface(ip_addr: str, iface: str) -> bool:
    """Enhanced check if an IP belongs to the local interface"""
    try:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            return any(addr['addr'] == ip_addr for addr in addrs[netifaces.AF_INET])
    except Exception as e:
        print(f"Error checking local interface: {e}")
    return False

def get_manufacturer_from_mac(mac_addr: str) -> Optional[str]:
    """Get manufacturer name from MAC address prefix"""
    mac_prefix = mac_addr[:8].lower()
    return MAC_PREFIXES.get(mac_prefix)

def discover_mdns_hosts(scan_time=15) -> Dict[str, dict]:
    """Enhanced mDNS discovery with better error handling"""
    zeroconf = Zeroconf()
    listener = MDNSListener()
    
    # Only try dns-sd on macOS
    if platform.system() == 'Darwin':
        try:
            subprocess.run(["dns-sd", "-B", "_apple-mobdev2._tcp", "local."], 
                         timeout=2, 
                         capture_output=True)
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            print(f"Warning: dns-sd command failed: {e}")

    service_types = [
        "_workstation._tcp.local.",
        "_companion-link._tcp.local.",
        "_apple-mobdev2._tcp.local.",
        "_googlecast._tcp.local.",
        "_androidtvremote._tcp.local.",
        "_raop._tcp.local.",
        "_airplay._tcp.local.",
        "_airport._tcp.local.",
        "_afpovertcp._tcp.local.",
        "_smb._tcp.local.",
        "_sftp-ssh._tcp.local.",
        "_ssh._tcp.local.",
        "_http._tcp.local.",
        "_https._tcp.local.",
        "_ipp._tcp.local.",
        "_ipps._tcp.local.",
        "_printer._tcp.local.",
        "_pdl-datastream._tcp.local.",
        "_scanner._tcp.local.",
        "_touch-able._tcp.local.",
        "_home-sharing._tcp.local.",
        "_apple-mobdev._tcp.local.",
        "_services._dns-sd._udp.local."
    ]
    
    print("Starting mDNS discovery...")
    browsers = []
    for service_type in service_types:
        try:
            browser = ServiceBrowser(zeroconf, service_type, listener)
            browsers.append(browser)
        except Exception as e:
            print(f"Error creating browser for {service_type}: {e}")
    
    time.sleep(scan_time)
    zeroconf.close()
    return listener.ip_to_info

def enhance_device_info(ip_addr: str, mac_addr: str, mdns_info: dict, iface: str, local_hostname: str) -> str:
    """Enhanced device identification with better local device handling"""
    # Normalize hostnames for comparison
    local_hostname = local_hostname.lower()
    
    # First check if this is the gateway/router
    try:
        default_gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
        if ip_addr == default_gateway:
            return "Router (Gateway Device)"
    except Exception:
        pass

    # Check if this is the local device using only reliable methods
    is_local = any([
        identify_local_interface(ip_addr, iface),
        mdns_info and mdns_info.get('is_local', False),
        mdns_info and mdns_info.get('name', '').lower() == local_hostname
    ])

    if is_local:
        return f"Local Host ({local_hostname})"

    if mdns_info:
        device_name = mdns_info.get('name', '').lower()
        service_type = mdns_info.get('type', '').lower()
        
        # Handle Android/Google devices
        if any(x in service_type for x in ['android', 'googlecast']):
            if 'bravia' in device_name:
                return "Sony Bravia TV (Android TV)"
            if '-' in device_name and len(device_name) > 30:  # Looks like a UUID
                return "Android TV Device"
            return "Android TV"
            
        elif 'ds423' in device_name:
            return "DS423.local"
            
        elif 'macbook air' in device_name or 'mba' in device_name:
            return f"MacBook Air ({device_name})"
            
        elif 'macbook' in device_name:
            return f"MacBook ({device_name})"
            
        elif 'imac' in device_name:
            return f"iMac ({device_name})"

        return device_name

    # Fallback to MAC prefix identification
    if mac_addr != "Unknown":
        manufacturer = get_manufacturer_from_mac(mac_addr)
        if manufacturer:
            return f"{manufacturer} device"

    return "Unknown device"

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced network scanner with improved metadata detection"
    )
    parser.add_argument(
        "--iface",
        help="Network interface to use (e.g., en0). Auto-detected if omitted."
    )
    parser.add_argument(
        "--network-range",
        help="CIDR range to scan (e.g., 192.168.3.0/24). Auto-detected if omitted."
    )
    parser.add_argument(
        "--scan-time",
        type=int,
        default=12,
        help="Time in seconds to scan for mDNS services (default: 12)"
    )
    parser.add_argument(
        "--no-arp",
        action="store_true",
        help="Skip ARP scanning (useful if you don't have promiscuous mode access)"
    )
    args = parser.parse_args()

    # Get local hostname
    local_hostname = get_local_hostname()
    print(f"Local hostname: {local_hostname}")

    # Auto-detect interface if not provided
    iface_to_use = args.iface or netifaces.gateways()["default"][netifaces.AF_INET][1]
    
    # Auto-detect network range if not provided
    if not args.network_range:
        addrs = netifaces.ifaddresses(iface_to_use)[netifaces.AF_INET][0]
        net_range = str(ipaddress.ip_network(
            f"{addrs['addr']}/{addrs['netmask']}", 
            strict=False
        ).compressed)
    else:
        net_range = args.network_range

    print(f"Using interface: {iface_to_use}")
    print(f"Scanning network range: {net_range}")

    # Gather mDNS information with increased timeout
    print(f"Discovering mDNS hosts ({args.scan_time}s)...")
    mdns_info = discover_mdns_hosts(scan_time=args.scan_time)

    # Configure Scapy
    conf.iface = iface_to_use

    # Initialize empty result
    result = []

    # Try to get system ARP cache first
    arp_cache = {}
    try:
        if platform.system() == 'Darwin':  # macOS
            arp_output = subprocess.check_output(['arp', '-an']).decode()
            for line in arp_output.split('\n'):
                if '(' in line and ')' in line:
                    ip = line[line.find('(')+1:line.find(')')]
                    mac = line.split(' at ')[-1].split(' ')[0]
                    if mac != '(incomplete)':
                        arp_cache[ip] = mac
    except Exception as e:
        print(f"Note: Couldn't read system ARP cache: {e}")

    # Only perform ARP scan if not disabled and we have root privileges
    if not args.no_arp:
        if os.geteuid() != 0:
            print("\nError: ARP scanning requires root privileges.")
            print("Please run with sudo or use --no-arp flag:")
            print(f"sudo {sys.argv[0]} {' '.join(sys.argv[1:])}")
            print("Running with only mDNS discovery...\n")
        else:
            try:
                print("Sending ARP requests...")
                conf.promisc = False
                arp_req = ARP(pdst=net_range)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                # Increase timeout and retry
                result = srp(ether / arp_req, timeout=5, retry=2, verbose=1)[0]
                print(f"Received {len(result)} ARP responses")
            except Exception as e:
                print(f"\nWarning: ARP scan failed: {e}")
                print("Try running with --no-arp flag if you don't have permission for promiscuous mode.")
                print("The script will still show mDNS discovered devices.\n")

    # Process results
    discovered_hosts = {}  # Use dict to track hosts by IP
    
    # Add mDNS-discovered hosts
    for ip_addr, info in mdns_info.items():
        if ip_addr.startswith("192.168."):
            # Try multiple methods to get MAC address
            mac_addr = "Unknown"
            
            # Method 1: Check system ARP cache
            if ip_addr in arp_cache:
                mac_addr = arp_cache[ip_addr]
            
            # Method 2: Try direct ARP request if we have root
            elif os.geteuid() == 0:
                try:
                    arp_req = ARP(pdst=ip_addr)
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                    result = srp(ether / arp_req, timeout=2, verbose=0)[0]
                    if result:
                        mac_addr = result[0][1].hwsrc
                except Exception:
                    pass
            
            metadata = enhance_device_info(
                ip_addr,
                mac_addr,
                info,
                iface_to_use,
                local_hostname
            )
            discovered_hosts[ip_addr] = (ip_addr, mac_addr, metadata)

    # Add ARP-discovered hosts
    for sent, received in result:
        ip_addr = received.psrc
        mac_addr = received.hwsrc
        
        if ip_addr.startswith("192.168."):
            metadata = enhance_device_info(
                ip_addr,
                mac_addr,
                mdns_info.get(ip_addr, {}),
                iface_to_use,
                local_hostname
            )
            # Update existing entry or add new one
            if ip_addr in discovered_hosts:
                # Update MAC address if it was unknown
                if discovered_hosts[ip_addr][1] == "Unknown":
                    discovered_hosts[ip_addr] = (ip_addr, mac_addr, metadata)
            else:
                discovered_hosts[ip_addr] = (ip_addr, mac_addr, metadata)

    # Convert to list and sort
    unique_hosts = sorted(discovered_hosts.values())

    # Print results
    if not unique_hosts:
        print("\nNo hosts discovered.")
        return

    print("\nDiscovered hosts:\n")
    print(f"{'IP Address':<15}  {'MAC Address':<17}  {'Metadata'}")
    print("-" * 60)
    for ip_addr, mac_addr, info in unique_hosts:
        print(f"{ip_addr:<15}  {mac_addr:<17}  {info}")

if __name__ == "__main__":
    main()