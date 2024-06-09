import ipaddress
import subprocess
import sqlite3
import time
import platform

# Function to ping an IP address
def ping_ip(ip):
    try:
        param = "-n" if platform.system().lower() == 'windows' else '-c'
        timeout = '-w' if platform.system().lower() == 'windows' else '-W'
        output = subprocess.check_output(['ping', param, '1', timeout, '1', str(ip)], stderr=subprocess.STDOUT, universal_newlines=True)

        # Check output for success
        if platform.system().lower() == "windows":
            # Windows ping success check
            if "Received = 1" in output:
                return True
        else:
            # Unix-like ping success check
            if "1 packets transmitted, 1 received" in output or "1 received" in output:
                return True
    except subprocess.CalledProcessError as e:
        print(f"Ping failed for {ip}: {e}")
    return False

# Function to get ARP table entries
def get_arp_table():
    arp_table = []
    if platform.system().lower():
        output = subprocess.check_output(['arp', '-a'], universal_newlines=True)
        for line in output.split('\n'):
            if '-' in line:
                parts = line.split()
                ip = parts[0]
                arp_table.append(ip)
    else:
        output = subprocess.check_output(['arp', '-n'], universal_newlines=True)
        for line in output.split('\n'):
            if 'at' in line:
                parts = line.split()
                ip = parts[1]
                arp_table.append(ip)
    
    return arp_table

# Function to scan a network range
def scan_network(network):
    ip_list = []
    net = ipaddress.ip_network(network)
    broadcast_ip = str(net.broadcast_address)

    # Check IPs in the network using ping
    for ip in net.hosts():
        print(f"Pinging {ip}...")
        if ping_ip(ip):
            ip_list.append(str(ip))
            print(f"Active IP found: {ip}")

    arp_table = get_arp_table()
    for ip in arp_table:
        try:
            # Validate if the IP is within the specified network
            if ipaddress.ip_address(ip) in net and ip != broadcast_ip:
                if ip not in ip_list:
                    ip_list.append(ip)
                    print(f"Active IP found from ARP table: {ip}")
        except ValueError:
            # Skip invalid IP addresses
            continue
    
    return ip_list

# Function to store Ips in SQLite database
def store_ips(ip_list):
    conn = sqlite3.connect("network_scanner.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS active_ips (ip TEXT, scanned_at TIMESTAMP)''')
    for ip in ip_list:
        cursor.execute("INSERT INTO active_ips (ip, scanned_at) VALUES (?, ?)", (ip, time.time()))

    conn.commit()
    conn.close()

def main():
    network = input("Enter the network/CIDR block (e.g., 192.168.1.0/24): ")
    ip_list = scan_network(network)
    store_ips(ip_list)
    print(f"Active IPs: {ip_list}")

if __name__ == "__main__":
    main()