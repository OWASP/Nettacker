import json
import threading
from ftplib import FTP
from core.alert import *
from core._time import now
from core.targets import target_type
from core.log import __log_into_file

PORT = 21

def extra_requirements_dict():
    return {}

def check(target, port ,language, scan_id, scan_cmd, log_in_file, timeout_sec):
    try:
        ftp = FTP()
        ftp.connect(target, port, timeout=timeout_sec)
        ftp.login('anonymous', 'me@test.you')
        ftp.quit()
        resp = '[*] ' + str(target) + ' Login Succeeded on port: ' + str(port)
        info(messages(language, "show_ftp_results").format(resp))
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': str(port),
                           'TYPE': 'ftp_scan', 'DESCRIPTION': str(resp),
                           'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
    except:        
        resp = '[*] ' + str(target) + ' Login Failed on port: ' + str(port)
        warn(messages(language, "show_ftp_results").format(resp))
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': str(port),
                           'TYPE': 'ftp_scan', 'DESCRIPTION': str(resp),
                           'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
    __log_into_file(log_in_file, 'a', data, language)

def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, language,
          verbose_level, show_version , socks_proxy, retries, ping_flag, scan_id,
          scan_cmd):  # Main function
    threads = []
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        if ports is not None:
            for port in ports:
                t = threading.Thread(target=check, args=(target, int(port), language, scan_id, scan_cmd, log_in_file, timeout_sec,))
                threads.append(t)
                t.start() 
        else:
            check(target, PORT, language, scan_id, scan_cmd, log_in_file, timeout_sec)
        for t in threads:
            t.join()
