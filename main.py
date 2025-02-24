#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import subprocess
import time

import netifaces
from scapy.all import ARP, Ether, srp, conf
from zeroconf import ServiceBrowser, Zeroconf, ServiceInfo

# -------------------------------------------------------------
# Step 1: We use netifaces to auto-detect our default interface
# and subnet (e.g., 192.168.3.0/24).
# -------------------------------------------------------------
def guess_wifi_iface():
    """
    Returns the default interface (e.g., 'en0' on macOS),
    via netifaces.gateways().
    """
    gateways = netifaces.gateways()
    default_iface = gateways["default"][netifaces.AF_INET][1]
    return default_iface

def guess_network_range(iface):
    """
    Returns something like '192.168.3.0/24' based on the IP and netmask
    from the given interface using netifaces.
    """
    addrs = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
    ip_addr = addrs["addr"]       # e.g. 192.168.3.52
    netmask = addrs["netmask"]    # e.g. 255.255.255.0
    network = ipaddress.ip_network(f"{ip_addr}/{netmask}", strict=False)
    return str(network.compressed)

# -------------------------------------------------------------
# Step 2: mDNS/Bonjour discovery with Zeroconf
# We'll store IP => "mDNS hostname" in a dictionary after
# scanning for ~5 seconds.
# -------------------------------------------------------------
class MDNSListener:
    def __init__(self):
        # We'll store IP => hostname here
        self.ip_to_name = {}

    def add_service(self, zeroconf, service_type, name):
        info = zeroconf.get_service_info(service_type, name)
        if info:
            # info.addresses can hold one or more IP addresses
            # We decode them from bytes to a standard string
            for raw_ip in info.addresses:
                # Each raw_ip might look like b'\xc0\xa8\x03\x35' for 192.168.3.53
                ip_str = socket.inet_ntoa(raw_ip)
                # The "server" field often has something like b'MyMacBook.local.'
                # We'll decode and strip trailing period
                mdns_host = info.server.decode('utf-8').rstrip('.')
                self.ip_to_name[ip_str] = mdns_host

def discover_mdns_hosts(scan_time=5):
    """
    Starts a Zeroconf browser for _workstation._tcp.local. (typical mDNS announcements).
    Waits scan_time seconds, then returns a dict { '192.168.x.x': 'MyDevice.local' }
    """
    zeroconf = Zeroconf()
    listener = MDNSListener()
    # We'll scan for general workstation announcements
    ServiceBrowser(zeroconf, "_workstation._tcp.local.", listener)

    # Sleep to allow mDNS packets to arrive
    time.sleep(scan_time)

    zeroconf.close()
    return listener.ip_to_name

# -------------------------------------------------------------
# Step 3: OS Fingerprinting or extra info via Nmap -O
# We'll parse the output for a "Running:" or "OS details:" line.
# This won't always give a hostname, but might give us OS info.
# -------------------------------------------------------------
def nmap_os_fingerprint(ip_addr):
    """
    Runs 'nmap -O <ip_addr>' in a subprocess, returns a short
    string summarizing OS or None if not detected.
    Must have nmap installed, typically requires sudo for OS detection.
    """
    try:
        # -n => no DNS resolution, -Pn => treat hosts as up, -O => OS detection
        output = subprocess.check_output(
            ["nmap", "-n", "-Pn", "-O", ip_addr],
            stderr=subprocess.STDOUT,
            timeout=15
        ).decode()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None

    # Look for lines like:
    # "Running: Apple macOS 11.X|12.X"
    # "OS details: Apple Mac OS X 10.8 - 10.11"
    # If nmap can't guess OS, it might say: "No exact OS matches"
    os_info = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Running:"):
            os_info = line.replace("Running: ", "").strip()
            break
        if line.startswith("OS details:"):
            os_info = line.replace("OS details:", "").strip()
            break

    return os_info

# -------------------------------------------------------------
# Main scanning function
# -------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="List IPv4 addresses on our local network using ARP scanning, then gather metadata via mDNS or nmap.")
    parser.add_argument(
        "--iface",
        default=None,
        help="Network interface to use (e.g., en0). If omitted, auto-detect default interface."
    )
    parser.add_argument(
        "--network-range",
        default=None,
        help="CIDR range to scan (e.g., 192.168.3.0/24). If omitted, auto-detect from the interface."
    )
    parser.add_argument(
        "--no-nmap",
        action="store_true",
        help="If set, skip nmap OS fingerprinting step."
    )
    parser.add_argument(
        "--no-mdns",
        action="store_true",
        help="If set, skip mDNS scanning step."
    )
    args = parser.parse_args()

    # Auto-detect interface if not provided
    iface_to_use = args.iface if args.iface else guess_wifi_iface()
    # Auto-detect network range if not provided
    if not args.network_range:
        net_range = guess_network_range(iface_to_use)
    else:
        net_range = args.network_range

    print(f"Using interface: {iface_to_use}")
    print(f"Scanning network range: {net_range}")

    # Step 2: Possibly gather mDNS hostnames first
    mdns_map = {}
    if not args.no_mdns:
        print("Discovering mDNS hosts (5s)...")
        mdns_map = discover_mdns_hosts(scan_time=5)

    # Configure Scapy to use the chosen interface
    conf.iface = iface_to_use

    # ARP scan
    arp_req = ARP(pdst=net_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether / arp_req, timeout=2, verbose=0)[0]

    # We'll store final data in a list of tuples: (ip, mac, metadata)
    discovered_hosts = []

    for sent, received in result:
        ip_addr = received.psrc
        mac_addr = received.hwsrc
        # Only track 192.168.* if that's our preference
        if ip_addr.startswith("192.168."):
            # 1) Attempt mDNS name
            mdns_name = mdns_map.get(ip_addr)

            # 2) If no mDNS name and we allow nmap, try nmap OS fingerprint
            #    This won't usually give a host "name," but might give OS info.
            os_info = None
            if not mdns_name and not args.no_nmap:
                os_info = nmap_os_fingerprint(ip_addr)

            # Decide the "best" metadata
            if mdns_name:
                metadata = mdns_name
            elif os_info:
                metadata = os_info
            else:
                metadata = "not detected"

            discovered_hosts.append((ip_addr, mac_addr, metadata))

    # Print a simple table
    print("\nDiscovered hosts:\n")
    print(f"{'IP Address':<15}  {'MAC Address':<17}  {'Metadata'}")
    print("-" * 60)
    for ip_addr, mac_addr, info in sorted(discovered_hosts):
        print(f"{ip_addr:<15}  {mac_addr:<17}  {info}")

if __name__ == "__main__":
    main()