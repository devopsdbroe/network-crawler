import logging
from network_scanner import scan_network
from database import store_ips
from utils import is_admin

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
