import sys
import json
import libnfs
from core.alert import *
from core._time import now
from subprocess import Popen, PIPE
from core.targets import target_type
from core.log import __log_into_file


def extra_requirements_dict():
    return {}

def check(target, language, scan_id, scan_cmd, log_in_file):
    import platform
    if platform.system() == "Windows":
        error(messages(language, "windows_error"))
        sys.exit(0)
    try:
        Popen(["showmount"], stdout=PIPE, stderr=PIPE)
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            error(messages(language, "showmount_error"))
            sys.exit(0) 

    shares = []
    response = []
    raw = Popen(["showmount", "-e", target], stdout=PIPE, stderr=PIPE)
    output, error = raw.communicate()
    if raw.returncode == 0:
        tmp = output.split("\n")[1:-1]
        for i in tmp:
            shares.append(i[:i.index(" ")])

        response.append( "[*] IP: " + target)
        response.append( "\tShared Resources: ")
        for share in shares:
            response.append( "\t    " + share)

        for path in shares:
            nfs_addr = "nfs://" + target + path
            response.append( "\tFiles on: " + nfs_addr)
            nfs = libnfs.NFS(nfs_addr)
            files = nfs.listdir('')
            for f in files:
                response.append( "\t\t" + f)
        for resp in response:
            info(messages(language, "show_nfs_results").format(resp))
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                           'TYPE': 'nfs_scan', 'DESCRIPTION': str(response),
                           'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
    else:
        warn(messages(language, "nfs_not_found").format(target, error))
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                           'TYPE': 'nfs_scan', 'DESCRIPTION': "no network share found on ip: " + target + " .. " + error,
                           'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"

    __log_into_file(log_in_file, 'a', data, language)

def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, language,
          verbose_level, show_version , socks_proxy, retries, ping_flag, scan_id,
          scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        check(target, language, scan_id, scan_cmd, log_in_file)
