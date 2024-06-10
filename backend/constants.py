import logging
import platform
import os
from datetime import datetime

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
