import sqlite3
import logging
from constants import DB_NAME

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
                logging.info(f"Storing IP info: {ip_info['ip']}")
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
