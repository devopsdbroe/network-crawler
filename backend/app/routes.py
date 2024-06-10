from flask import Blueprint, request, jsonify
import logging
from network_scanner import scan_network
from database import store_ips, get_stored_ips

main = Blueprint('main', __name__)

@main.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        network = data.get('network')
        ip_list = scan_network(network)
        store_ips(ip_list)
        logging.info(f"Number of IPs found: {len(ip_list)}")
        logging.info(f"Active IPs: {ip_list}")
        return jsonify(ip_list), 200
    except Exception as e:
        logging.error("An error occurred during the execution of the scan", exc_info=True)
        return jsonify({'error': 'An error occurred during the scan'}), 500

@main.route('/ips', methods=['GET'])
def ips():
    try:
        ips = get_stored_ips()
        return jsonify(ips), 200
    except Exception as e:
        logging.error("An error occurred while retrieving stored IPs", exc_info=True)
        return jsonify({'error': 'An error occurred while retrieving stored IPs'}), 500
