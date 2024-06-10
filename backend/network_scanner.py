import platform
import subprocess
import socket
import psutil
import nmap
import logging
from scapy.all import ARP, Ether, srp

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import ipaddress

from constants import PING_PARAM, TIMEOUT_PARAM, WINDOWS_SUCCESS, UNIX_SUCCESS
from utils import is_admin

# Function to ping an IP address
def ping_ip(ip):
    try:
        logging.info(f"Pinging IP: {ip}")
        output = subprocess.check_output(
            ["ping", PING_PARAM, "1", TIMEOUT_PARAM, "1", str(ip)],
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )

        # Check output for success
        # Windows ping success check
        if platform.system().lower() == "windows" and WINDOWS_SUCCESS in output:
            return True
        # Unix-like ping success check
        elif any(success_msg in output for success_msg in UNIX_SUCCESS):
            return True
    except subprocess.CalledProcessError as e:
        # Log ping failure
        logging.debug(f"Ping failed for {ip}: {e}")

    # Return False if ping wasn't successful
    return False


# Function to get ARP table entries
def get_arp_table(network):
    arp_table = []
    try:
        logging.info("Retrieving ARP table")
        arp_request = ARP(pdst=str(network))
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        for sent, received in answered_list:
            arp_table.append({'ip': received.psrc, 'mac': received.hwsrc})
    except Exception as e:
        logging.error(f"Failed to retrieve ARP table: {e}")
    return arp_table

# Function to get OS and device type using psutil
def get_os_device_info(ip):
    try:
        logging.info(f"Getting OS and device info for IP: {ip}")
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.ip == ip:
                return platform.system(), conn.pid
    except Exception as e:
        logging.error(f"Failed to get OS/device info for {ip}: {e}")
    return None, None

# Function to get hostname
def get_hostname(ip):
    try:
        logging.info(f"Getting hostname for IP: {ip}")
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

# Function to get open ports and service banners using nmap
def get_open_ports(ip):
    open_ports = []
    service_banner = None
    try:
        logging.info(f"Scanning open ports for IP: {ip}")
        nm = nmap.PortScanner()
        nm.scan(ip, '22, 80, 443', arguments='-T4 --max-retries 1 --host-timeout 30s') # Limit port scanning for demonstration purposes
        for proto in nm[ip].all_protocols():
            lport = nm[ip][proto].keys()
            for port in lport:
                open_ports.append(port)
                service_banner = nm[ip][proto][port]['product']
    except Exception as e:
        logging.error(f"Failed to get open ports for {ip}: {e}")
    return open_ports, service_banner

# Function to scan a network range
def scan_network(network):
    results = []

    try:
        logging.info(f"Scanning network: {network}")
        net = ipaddress.ip_network(network)
    except ValueError:
        logging.error("Invalid network address provided.")
        return results

    broadcast_ip = str(net.broadcast_address)
    with ThreadPoolExecutor(max_workers=10) as executor:
        ping_results = list(executor.map(ping_ip, net.hosts()))

    arp_table = get_arp_table(network)
    current_time = datetime.now()

    for ip, is_active in zip(net.hosts(), ping_results):
        if is_active:
            ip_info = {
                'ip': str(ip),
                'is_active': is_active,
                'os': None,
                'hostname': get_hostname(str(ip)),
                'latency': None,
                'mac_address': None,
                'device_type': None,
                'open_ports': None,
                'service_banner': None,
                'device_registration_time': None,
                'scan_time': current_time
            }
            results.append(ip_info)

    for entry in arp_table:
        ip = entry['ip']
        mac_address = entry['mac']
        if ip in [result['ip'] for result in results]:
            continue
        os, device_type = get_os_device_info(ip)
        open_ports, service_banner = get_open_ports(ip)
        ip_info = {
            'ip': ip,
            'is_active': True,
            'os': os,
            'hostname': get_hostname(ip),
            'latency': None,
            'mac_address': mac_address,
            'device_type': device_type,
            'open_ports': open_ports,
            'service_banner': service_banner,
            'device_registration_time': None,
            'scan_time': current_time
        }
        results.append(ip_info)

    return results
