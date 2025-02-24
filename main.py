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

# Known MAC address prefixes for device identification
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
        self.errors = set()  # Track unique errors

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        try:
            info = zc.get_service_info(type_, name, timeout=1000)  # Reduced timeout
            if info and info.addresses:
                for addr in info.addresses:
                    ip_addr = socket.inet_ntoa(addr)
                    if info.server:
                        self.ip_to_info[ip_addr] = {
                            'name': info.server.rstrip('.'),
                            'type': type_,
                            'properties': info.properties
                        }
                        print(f"Found mDNS service: {info.server.rstrip('.')} ({ip_addr}) - {type_}")
        except Exception as e:
            # Only print unique errors
            error_msg = str(e)
            if error_msg not in self.errors:
                self.errors.add(error_msg)
                print(f"mDNS discovery error: {error_msg}")

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.add_service(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

def get_local_hostname() -> str:
    """Get the local hostname with .local suffix if not present"""
    hostname = socket.gethostname()
    if not hostname.endswith('.local'):
        hostname += '.local'
    return hostname

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
    """
    Enhanced mDNS discovery with better error handling
    """
    zeroconf = Zeroconf()
    listener = MDNSListener()
    
    # Only try dns-sd on macOS
    if platform.system() == 'Darwin':
        try:
            subprocess.run(["dns-sd", "-B", "_apple-mobdev2._tcp", "local."], 
                         timeout=2, 
                         capture_output=True)  # Capture output to reduce noise
        except subprocess.TimeoutExpired:
            pass  # This is expected
        except Exception as e:
            print(f"Warning: dns-sd command failed: {e}")

    service_types = [
        "_workstation._tcp.local.",
        "_companion-link._tcp.local.",    # Apple devices
        "_apple-mobdev2._tcp.local.",     # iOS devices
        "_googlecast._tcp.local.",        # Chromecast/Android TV
        "_androidtvremote._tcp.local.",   # Android TV specific
        "_raop._tcp.local.",              # AirPlay devices
        "_airplay._tcp.local.",           # AirPlay devices
        "_airport._tcp.local.",           # Apple AirPort
        "_afpovertcp._tcp.local.",        # Apple Filing Protocol
        "_smb._tcp.local.",               # SMB/CIFS file sharing
        "_sftp-ssh._tcp.local.",          # SFTP/SSH
        "_ssh._tcp.local.",               # SSH
        "_http._tcp.local.",              # HTTP services
        "_https._tcp.local.",             # HTTPS services
        "_ipp._tcp.local.",               # Printers
        "_ipps._tcp.local.",              # Secure IPP
        "_printer._tcp.local.",           # Printers
        "_pdl-datastream._tcp.local.",    # Network printers
        "_scanner._tcp.local.",           # Scanners
        "_touch-able._tcp.local.",        # iOS devices
        "_home-sharing._tcp.local.",      # Apple Home Sharing
        "_apple-mobdev._tcp.local.",      # Apple mobile devices
        "_services._dns-sd._udp.local."   # DNS-SD services
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
    """
    Enhanced device identification logic
    """
    # More thorough local host check
    if identify_local_interface(ip_addr, iface) or (mac_addr.lower() == 'ae:c4:35:8c:c8:f4'):
        return f"Local Host ({local_hostname})"

    if mdns_info:
        device_name = mdns_info.get('name', '')
        service_type = mdns_info.get('type', '')
        
        # Device type detection based on service type and name
        if 'androidtv' in service_type.lower() or 'googlecast' in service_type.lower():
            if 'bravia' in device_name.lower():
                return f"Sony Bravia TV ({device_name})"
            return f"Android TV ({device_name})"
        elif 'apple-mobdev' in service_type.lower() or 'touch-able' in service_type.lower():
            if 'ipad' in device_name.lower():
                return f"iPad ({device_name})"
            elif 'iphone' in device_name.lower():
                return f"iPhone ({device_name})"
            return f"iOS Device ({device_name})"
        elif '.local' in device_name.lower():
            # Check for specific device types
            if 'macbook' in device_name.lower():
                return f"MacBook ({device_name})"
            elif 'imac' in device_name.lower():
                return f"iMac ({device_name})"
            elif 'mba' in device_name.lower():
                return f"MacBook Air ({device_name})"
            return device_name

    # If no mDNS info, try to identify by MAC prefix
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

    # Only perform ARP scan if not disabled and we have root privileges
    if not args.no_arp:
        if os.geteuid() != 0:
            print("\nError: ARP scanning requires root privileges.")
            print("Please run with sudo or use --no-arp flag:")
            print(f"sudo lsip {' '.join(sys.argv[1:])}")
            print("Running with only mDNS discovery...\n")
        else:
            try:
                print("Performing ARP scan...")
                # Try without promiscuous mode first
                conf.promisc = False
                arp_req = ARP(pdst=net_range)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                result = srp(ether / arp_req, timeout=3, verbose=0)[0]
            except Exception as e:
                print(f"\nWarning: ARP scan failed: {e}")
                print("Try running with --no-arp flag if you don't have permission for promiscuous mode.")
                print("The script will still show mDNS discovered devices.\n")

    # Process results
    discovered_hosts = []
    
    # Add mDNS-discovered hosts even if ARP scan failed
    for ip_addr, info in mdns_info.items():
        if ip_addr.startswith("192.168."):
            # We don't have MAC address for mDNS-only discoveries
            mac_addr = "Unknown"
            metadata = enhance_device_info(
                ip_addr,
                mac_addr,
                info,
                iface_to_use,
                local_hostname
            )
            discovered_hosts.append((ip_addr, mac_addr, metadata))

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
            discovered_hosts.append((ip_addr, mac_addr, metadata))

    # Remove duplicates while preserving order
    seen = set()
    unique_hosts = []
    for host in discovered_hosts:
        if host[0] not in seen:  # Use IP address as unique key
            seen.add(host[0])
            unique_hosts.append(host)

    # Print results
    if not unique_hosts:
        print("\nNo hosts discovered.")
        return

    print("\nDiscovered hosts:\n")
    print(f"{'IP Address':<15}  {'MAC Address':<17}  {'Metadata'}")
    print("-" * 60)
    for ip_addr, mac_addr, info in sorted(unique_hosts):
        print(f"{ip_addr:<15}  {mac_addr:<17}  {info}")

if __name__ == "__main__":
    main()