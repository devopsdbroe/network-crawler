import ipaddress
import subprocess
import sqlite3
import time
import platform
import logging
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Constants for cross-platfrom compatibility
PING_PARAM = "-n" if platform.system().lower() == "windows" else "-c"
TIMEOUT_PARAM = "-w" if platform.system().lower() == "windows" else "-W"
WINDOWS_SUCCESS = "Received = 1"
UNIX_SUCCESS = ["1 packets transmittedd, 1 received", "1 received"]
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
def get_arp_table():
    arp_table = []

    try:
        # Determine the arp command based on operating system
        command = (
            ["arp", "-a"] if platform.system().lower() == "windows" else ["arp", "-n"]
        )

        # Run the arp command and capture the output
        output = subprocess.check_output(command, universal_newlines=True)

        # Parse the output to extract the IP Addresses
        for line in output.split("\n"):
            if "-" in line or "at" in line:
                parts = line.split()
                ip = parts[0] if platform.system().lower() == "windows" else parts[1]
                arp_table.append(ip)
    except subprocess.CalledProcessError as e:
        # Log ARP table retrieval failure
        logging.error(f"Failed to retieve ARP table: {e}")

    return arp_table


# Function to scan a network range
def scan_network(network):
    ip_list = []

    try:
        net = ipaddress.ip_network(network)  # Create an IP network object
    except ValueError:
        # Log invalid network address
        logging.error("Invalid network address provided.")
        return ip_list

    broadcast_ip = str(
        net.broadcast_address
    )  # Get the broadcast IP address of the network

    # Use a thread pool to ping muliple IPs concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(ping_ip, net.hosts()))

    # Collect IPs that responded to the ping
    for ip, result in zip(net.hosts(), results):
        if result:
            ip_list.append(str(ip))
            logging.info(f"Active IP found: {ip}")

    # Retrieve and validate IPs from the ARP table
    arp_table = get_arp_table()
    for ip in arp_table:
        try:
            if (
                ipaddress.ip_address(ip) in net
                and ip != broadcast_ip
                and ip not in ip_list
            ):
                ip_list.append(ip)
                logging.info(f"Active IP found from ARP table: {ip}")
        except ValueError:
            continue

    return ip_list


# Function to store IPs in SQLite database
def store_ips(ip_list):
    with sqlite3.connect(DB_NAME) as conn:  # Connect to SQLite database
        cursor = conn.cursor()

        # Create table if it doesn't exist
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS active_ips (ip TEXT, scanned_at TIMESTAMP)"""
        )

        # Insert each active IP address into the database
        for ip in ip_list:
            cursor.execute(
                "INSERT INTO active_ips (ip, scanned_at) VALUES (?, ?)",
                (ip, time.time()),
            )

    conn.commit()
    conn.close()


def main():
    try:
        network = input("Enter the network/CIDR block (e.g., 192.168.1.0/24): ")
        ip_list = scan_network(network)
        store_ips(ip_list)
        logging.info(f"Number of IPs found: {len(ip_list)}")
        logging.info(f"Active IPs: {ip_list}")
    except Exception as e:
        logging.error("An error occured during the execution of the script", exc_info=True)
        raise


if __name__ == "__main__":
    main()
