import os
import ctypes
import sys
import logging

def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    
if not is_admin():
    logging.error("This script must be run as root. Exiting.")
    sys.exit(1)
