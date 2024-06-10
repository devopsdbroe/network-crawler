import ipaddress
import subprocess
import sqlite3
import time
import platform
import logging
import os
import socket
import psutil
import nmap
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp

# Constants for cross-platform compatibility
PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"
TIMEOUT_PARAM = "-w" if platform.system().lower() == "windows" else "-W"
WINDOWS_SUCCESS = "Received = 1"
UNIX_SUCCESS = ["1 packets transmitted, 1 received", "1 received"]
DB_NAME = "network_scanner.db"

# Define log directory and ensure it exists
log_directory = "logs"
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Configure logging
log_filename = os.path.join(log_directory, datetime.now().strftime("network_scan%Y%m%d_%H%M%S.log"))
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)

# Function to ping an IP address
def ping_ip(ip):
    try:
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
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.ip == ip:
                return platform.system(), conn.pid
    except Exception as e:
        logging.error(f"Failed to get OS/device info for {ip}: {e}")
    return None, None

# Function to get hostname
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

# Function to get open ports and service banners using nmap
def get_open_ports(ip):
    open_ports = []
    service_banner = None
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1024')
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

# Function to store IPs in SQLite database
def store_ips(ip_list):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS active_ips (
                ip TEXT UNIQUE,
                is_active BOOLEAN,
                os TEXT,
                hostname TEXT,
                latency REAL,
                mac_address TEXT,
                device_type TEXT,
                open_ports TEXT,
                service_banner TEXT,
                device_registration_time TEXT,
                scan_time TIMESTAMP
            )
        """)

        for ip_info in ip_list:
            try:
                cursor.execute("""
                    INSERT INTO active_ips (
                        ip, is_active, os, hostname, latency, mac_address,
                        device_type, open_ports, service_banner,
                        device_registration_time, scan_time
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip_info['ip'], ip_info['is_active'], ip_info['os'],
                    ip_info['hostname'], ip_info['latency'], ip_info['mac_address'],
                    ip_info['device_type'], ','.join(map(str, ip_info['open_ports'])),
                    ip_info['service_banner'], ip_info['device_registration_time'],
                    ip_info['scan_time']
                ))
            except sqlite3.IntegrityError:
                logging.warning(f"Duplicate IP not inserted: {ip_info['ip']}")

        conn.commit()

def get_stored_ips():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM active_ips")
        rows = cursor.fetchall()
    return rows

def main():
    try:
        network = input("Enter the network/CIDR block (e.g., 192.168.1.0/24): ")
        ip_list = scan_network(network)
        store_ips(ip_list)
        logging.info(f"Number of IPs found: {len(ip_list)}")
        logging.info(f"Active IPs: {ip_list}")
    except Exception as e:
        logging.error("An error occurred during the execution of the script", exc_info=True)
        raise

if __name__ == "__main__":
    main()
