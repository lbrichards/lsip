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
from scapy.all import ARP, Ether, srp, conf, TCP, IP, sr1
from zeroconf import ServiceBrowser, Zeroconf, ServiceListener

IOS_PORTS = {
    49152: "iOS device",  # Common iOS/iPadOS service port
    62078: "iOS device",  # iPhone/iPad sync port
    5900: "Apple Screen Sharing",
    3689: "iTunes sharing",
    548: "Apple Filing Protocol",
    88: "Kerberos",
    137: "NetBIOS",      # Sometimes used by iOS
    138: "NetBIOS",      # Sometimes used by iOS
    445: "SMB",          # Sometimes used by iOS
    5353: "mDNS",        # Bonjour
    7000: "AirPlay",     # AirPlay for iOS devices
}

# Additional Bonjour service types for iOS detection - add to service_types list in discover_mdns_hosts
IPHONE_SERVICE_TYPES = [
    "_apple-mobdev2._tcp.local.",
    "_apple-pairable._tcp.local.",
    "_companion-link._tcp.local.",
    "_sleep-proxy._udp.local.",
    "_homekit._tcp.local.",
    "_touch-able._tcp.local.",
    "_ipp._tcp.local.",
    "_universal._sub._ipp._tcp.local.",
    "_printer._tcp.local.",
    "_scanner._tcp.local.",
    "_presence._tcp.local."
]

# Update the get_apple_device_type function with better iPhone detection:
def get_apple_device_type(ip_addr: str, mdns_info: dict) -> Optional[str]:
    """
    Enhanced iPhone detection
    """
    if not mdns_info:
        return None
        
    device_name = mdns_info.get('name', '').lower()
    service_type = mdns_info.get('service_types', '').lower()
    
    # Check device name for iPhone indicators
    iphone_indicators = ['iphone', 'iphon']  # Common misspellings/variants
    if any(indicator in device_name for indicator in iphone_indicators):
        return "iPhone"
        
    # Check for iPhone-specific service types
    if any(svc in service_type for svc in ['_apple-mobdev2.', '_companion-link.', '_apple-pairable.']):
        # Enhanced port scanning for iPhone detection
        ios_ports_found = 0
        for port in [49152, 62078, 7000]:  # Most distinctive iOS ports
            try:
                packet = IP(dst=ip_addr)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=1, verbose=0)
                if response and response.haslayer(TCP):
                    tcp_flags = response[TCP].flags
                    if tcp_flags == 0x12:  # SYN-ACK
                        ios_ports_found += 1
            except Exception:
                continue
                
        if ios_ports_found >= 2:  # If at least 2 iOS-specific ports are open
            return "iPhone"
            
    # Additional checks for iPhone-specific Bonjour services
    if '_companion-link._tcp.local.' in service_type and '_homekit._tcp.local.' in service_type:
        return "iPhone"
        
    return None



# Enhanced MAC address prefixes with specific Apple device types
MAC_PREFIXES = {
    # Network equipment
    '90:32:4b': 'RouterBoard',
    '90:09:d0': 'Synology',
    
    # Apple devices (expanded)
    'a8:8f:d9': 'Apple Mac',
    'ae:c4:35': 'Apple iPhone',
    '48:5f:99': 'Google',
    'b2:6a:53': 'Apple MacBook',
    'ce:b5:f8': 'Apple iMac',
    'ee:38:c5': 'Apple iPad',
    '04:15:52': 'Apple iPhone',
    '04:26:65': 'Apple iPhone',
    '14:99:e2': 'Apple iPhone',
    '70:56:81': 'Apple iPhone',
    '7c:50:49': 'Apple iPhone',
    '78:ca:39': 'Apple iPhone',
    'ac:bc:32': 'Apple iPhone',
    '68:d9:3c': 'Apple iPhone',
    'dc:2b:2a': 'Apple iPad',
    '00:88:65': 'Apple Mac Mini',
    '00:3e:e1': 'Apple Mac Pro',
}

# iOS/iPadOS-specific ports
IOS_PORTS = {
    49152: "iOS device",  # Common iOS/iPadOS service port
    62078: "iOS device",  # iPhone/iPad sync port
    5900: "Apple Screen Sharing",
    3689: "iTunes sharing",
    548: "Apple Filing Protocol",
    88: "Kerberos",
}


def enhance_device_info(ip_addr: str, mac_addr: str, mdns_info: dict, iface: str, local_hostname: str) -> str:
    """Enhanced device identification with better iPhone detection"""
    # ... [previous gateway and local device checks remain the same]

    # Enhanced Apple device detection with focus on iPhones
    if mac_addr != "Unknown":
        # First check if this is definitely an iPhone based on MAC prefix
        mac_prefix = mac_addr[:8].lower()
        if mac_prefix in ['ae:c4:35', '04:15:52', '04:26:65', '14:99:e2', 
                         '70:56:81', '7c:50:49', '78:ca:39', 'ac:bc:32', '68:d9:3c']:
            if mdns_info and mdns_info.get('name'):
                return f"iPhone ({mdns_info['name']})"
            return "iPhone"
            
        # Otherwise try other Apple device detection methods
        if any(prefix in mac_addr.lower() for prefix in MAC_PREFIXES if 'Apple' in MAC_PREFIXES[prefix]):
            apple_device_type = get_apple_device_type(ip_addr, mdns_info)
            
            if apple_device_type:
                if mdns_info and mdns_info.get('name'):
                    return f"{apple_device_type} ({mdns_info['name']})"
                return apple_device_type




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
                            'is_local': server_name == self.local_hostname,
                            'service_types': type_  # Store full service type for better detection
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

def get_apple_device_type(ip_addr: str, mdns_info: dict) -> Optional[str]:
    """
    Determine specific Apple device type using multiple detection methods
    """
    if not mdns_info:
        return None
        
    device_name = mdns_info.get('name', '').lower()
    service_type = mdns_info.get('service_types', '').lower()
    
    # First check device name for clear indicators
    if 'ipad' in device_name:
        return "iPad"
    elif 'iphone' in device_name:
        return "iPhone"
    elif 'macbook' in device_name:
        return "MacBook"
    elif 'imac' in device_name:
        return "iMac"
    elif 'mac mini' in device_name or 'macmini' in device_name:
        return "Mac Mini"
    elif 'mac pro' in device_name:
        return "Mac Pro"
    
    # Then check service types
    if '_apple-mobdev2._tcp.local.' in service_type or '_apple-pairable._tcp.local.' in service_type:
        # Additional check for iOS-specific ports
        for port in [49152, 62078]:  # iPhone/iPad sync ports
            try:
                packet = IP(dst=ip_addr)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=1, verbose=0)
                if response and response.haslayer(TCP):
                    tcp_flags = response[TCP].flags
                    if tcp_flags == 0x12:  # SYN-ACK
                        return "iOS device"
            except Exception:
                continue
                
    # Additional service type checks
    if '_airplay._tcp.local.' in service_type:
        if any(mac_type in device_name for mac_type in ['macbook', 'imac', 'mac']):
            return "Mac"  # Generic Mac designation
            
    return None


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
        "_apple-pairable._tcp.local.",
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
    """Enhanced device identification with better Apple device detection"""
    # Normalize hostnames for comparison
    local_hostname = local_hostname.lower()
    
    # First check if this is the gateway/router
    try:
        default_gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
        if ip_addr == default_gateway:
            return "Router (Gateway Device)"
    except Exception:
        pass

    # Check if this is the local device
    is_local = any([
        identify_local_interface(ip_addr, iface),
        mdns_info and mdns_info.get('is_local', False),
        mdns_info and mdns_info.get('name', '').lower() == local_hostname
    ])

    if is_local:
        return f"Local Host ({local_hostname})"

    # Enhanced Apple device detection
    if mac_addr != "Unknown" and any(prefix in mac_addr.lower() for prefix in MAC_PREFIXES if 'Apple' in MAC_PREFIXES[prefix]):
        # Try to get specific Apple device type
        apple_device_type = get_apple_device_type(ip_addr, mdns_info)
        
        if apple_device_type:
            if mdns_info and mdns_info.get('name'):
                return f"{apple_device_type} ({mdns_info['name']})"
            return apple_device_type
        
        # Fallback to MAC prefix identification
        manufacturer = get_manufacturer_from_mac(mac_addr)
        if manufacturer:
            if mdns_info and mdns_info.get('name'):
                return f"{manufacturer} ({mdns_info['name']})"
            return manufacturer

    # Handle other device types
    if mdns_info:
        device_name = mdns_info.get('name', '').lower()
        service_type = mdns_info.get('type', '').lower()
        
        # Handle Android/Google devices
        if any(x in service_type for x in ['android', 'googlecast']):
            if 'bravia' in device_name:
                return "Sony Bravia TV (Android TV)"
            if '-' in device_name and len(device_name) > 30:  # Looks like a UUID
                return "Android TV Device"
            return "Android Device"
            
        elif 'ds423' in device_name:
            return "Synology NAS (DS423)"
            
        return device_name

    # Fallback to basic MAC prefix identification
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





