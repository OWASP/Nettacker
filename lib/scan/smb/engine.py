import re
import sys
import json
import socket
from smb import smb_structs
from nmb.NetBIOS import NetBIOS
from subprocess import Popen, PIPE
from smb.SMBConnection import SMBConnection

from core.alert import *
from core._time import now
from core.targets import target_type
from core.log import __log_into_file
from core.targets import target_to_host

smb_structs.SUPPORT_SMB2 = True


def extra_requirements_dict():
    return {}

def get_bios_name(ip):
    try:
        bios = NetBIOS()
        return bios.queryIPForName(ip, timeout=5)
    except:
        return False

def check(target, language, scan_id, scan_cmd, log_in_file, timeout_sec):
    userID = ''
    password = ''
    client_machine_name = socket.gethostname()
    tmp = get_bios_name(target)
    if tmp:
        server_name = tmp[0]
    else:
        server_name = 'X'
    domain_name = ''
    response = []
    try:
        conn = SMBConnection('', '', '', server_name, domain=domain_name, use_ntlm_v2=True, is_direct_tcp=True)
        conn.connect(target, 445)
        shares = conn.listShares(timeout=timeout_sec)
        response.append("[*] IP: " + target)
        response.append( "\tShared Resources: ")
        for share in shares:
            response.append( "\t    " + share.name)
        response.append( "\tFiles on: "+ server_name + "-->[" + target + "]")
        for share in shares:
            if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL']:
                sharedfiles = conn.listPath(share.name, '/')
                response.append( "\t\t[$] Share Name: " + share.name)
                for sharedfile in sharedfiles:
                    if sharedfile.isDirectory:
                        response.append( "\t\t\t[ d ] " + sharedfile.filename)
                    else:
                        response.append( "\t\t\t[ f ] " + sharedfile.filename)
        for resp in response:
            info(messages(language, "show_smb_results").format(resp))
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '445',
                           'TYPE': 'smb_scan', 'DESCRIPTION': str(response),
                           'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
    except Exception as e:
        warn(messages(language, "smb_not_found").format(target, e))
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '445',
                           'TYPE': 'smb_scan', 'DESCRIPTION': "No network share found on " + target,
                           'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
    __log_into_file(log_in_file, 'a', data, language)

def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, language,
          verbose_level, show_version , socks_proxy, retries, ping_flag, scan_id,
          scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        check(target, language, scan_id, scan_cmd, log_in_file, timeout_sec)
