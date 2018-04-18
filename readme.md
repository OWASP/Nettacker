OWASP Nettacker
=========
[![Build Status Travic CI](https://travis-ci.org/zdresearch/OWASP-Nettacker.svg?branch=master)](https://travis-ci.org/viraintel/OWASP-Nettacker)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/04ca57d1b996435d8a42c767add84859)](https://www.codacy.com/app/zdresearch/OWASP-Nettacker?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=zdresearch/OWASP-Nettacker&amp;utm_campaign=Badge_Grade)
[![Python 2.x](https://img.shields.io/badge/python-2.x-blue.svg)](https://travis-ci.org/viraintel/OWASP-Nettacker)
[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://travis-ci.org/viraintel/OWASP-Nettacker)
[![Apache License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://github.com/viraintel/OWASP-Nettacker/blob/master/LICENSE)
[![Executed](http://nettacker.z3r0d4y.com/update_counter.py)](https://github.com/viraintel/OWASP-Nettacker/)
[![Twitter](https://img.shields.io/badge/Twitter-@iotscan-blue.svg)](https://twitter.com/iotscan)


<img src="https://raw.githubusercontent.com/viraintel/OWASP-Nettacker/master/web/static/img/owasp-nettacker.png" width="200"><img src="https://raw.githubusercontent.com/viraintel/OWASP-Nettacker/master/web/static/img/owasp.png" width="500">



***THIS SOFTWARE WAS CREATED FOR AUTOMATED PENETRATION TESTING AND INFORMATION GATHERING. CONTRIBUTORS WILL NOT BE RESPONSIBLE FOR ANY ILLEGAL USAGE.***


![2018-01-19_0-45-07](https://user-images.githubusercontent.com/7676267/35123376-283d5a3e-fcb7-11e7-9b1c-92b78ed4fecc.gif)

OWASP Nettacker project is created to automate information gathering, vulnerability scanning and eventually generating a report for networks, including services, bugs, vulnerabilities, misconfigurations, and other information. This software **will** utilize TCP SYN, ACK, ICMP and many other protocols in order to detect and bypass Firewall/IDS/IPS devices. By leveraging a unique method in OWASP Nettacker for discovering protected services and devices such as SCADA. It would make a competitive edge compared to other scanner making it one of the bests.


* OWASP Page: https://www.owasp.org/index.php/OWASP_Nettacker
* Home: http://nettacker.z3r0d4y.com/
* Github: https://github.com/viraintel/OWASP-Nettacker
* Slack: https://owaspnettacker.slack.com
* Mailing List: https://groups.google.com/forum/#!forum/owasp-nettacker
* Docker Image: https://hub.docker.com/r/alirazmjoo/owaspnettacker/
* How to use the Dockerfile: https://github.com/viraintel/OWASP-Nettacker/wiki/Installationgit
* OpenHub: https://www.openhub.net/p/OWASP-Nettacker


```



   ______          __      _____ _____
  / __ \ \        / /\    / ____|  __ \
 | |  | \ \  /\  / /  \  | (___ | |__) |
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/
 | |__| | \  /\  / ____ \ ____) | |     Version 0.0.1
  \____/   \/  \/_/    \_\_____/|_|     SAME
                          _   _      _   _             _
                         | \ | |    | | | |           | |
  github.com/viraintel   |  \| | ___| |_| |_ __ _  ___| | _____ _ __
  owasp.org              | . ` |/ _ \ __| __/ _` |/ __| |/ / _ \ '__|
  viraintel.com          | |\  |  __/ |_| || (_| | (__|   <  __/ |
                         |_| \_|\___|\__|\__\__,_|\___|_|\_\___|_|



usage: Nettacker [-L LANGUAGE] [-v VERBOSE_LEVEL] [-V] [-c] [-o LOG_IN_FILE]
                 [--graph GRAPH_FLAG] [-h] [-W] [--profile PROFILE]
                 [-i TARGETS] [-l TARGETS_LIST] [-m SCAN_METHOD]
                 [-x EXCLUDE_METHOD] [-u USERS] [-U USERS_LIST] [-p PASSWDS]
                 [-P PASSWDS_LIST] [-g PORTS] [-T TIMEOUT_SEC] [-w TIME_SLEEP]
                 [-r] [-s] [-t THREAD_NUMBER] [-M THREAD_NUMBER_HOST]
                 [-R SOCKS_PROXY] [--retries RETRIES] [--ping-before-scan]
                 [--method-args METHODS_ARGS] [--method-args-list]
                 [--start-api] [--api-host API_HOST] [--api-port API_PORT]
                 [--api-debug-mode] [--api-access-key API_ACCESS_KEY]
                 [--api-client-white-list]
                 [--api-client-white-list-ips API_CLIENT_WHITE_LIST_IPS]
                 [--api-access-log]
                 [--api-access-log-filename API_ACCESS_LOG_FILENAME]

Engine:
  Engine input options

  -L LANGUAGE, --language LANGUAGE
                        select a language ['el', 'fr', 'en', 'nl', 'ps', 'tr',
                        'de', 'ko', 'it', 'ja', 'fa', 'hy', 'ar', 'zh-cn',
                        'vi', 'ru', 'hi', 'ur', 'id', 'es']
  -v VERBOSE_LEVEL, --verbose VERBOSE_LEVEL
                        verbose mode level (0-5) (default 0)
  -V, --version         show software version
  -c, --update          check for update
  -o LOG_IN_FILE, --output LOG_IN_FILE
                        save all logs in file (results.txt, results.html,
                        results.json)
  --graph GRAPH_FLAG    build a graph of all activities and information, you
                        must use HTML output. available graphs:
                        ['d3_tree_v1_graph', 'd3_tree_v2_graph',
                        'jit_circle_v1_graph']
  -h, --help            Show Nettacker Help Menu
  -W, --wizard          start wizard mode
  --profile PROFILE     select profile ['vulnerabilities',
                        'information_gathering', 'all']

Target:
  Target input options

  -i TARGETS, --targets TARGETS
                        target(s) list, separate with ","
  -l TARGETS_LIST, --targets-list TARGETS_LIST
                        read target(s) from file

Method:
  Scan method options

  -m SCAN_METHOD, --method SCAN_METHOD
                        choose scan method ['admin_scan', 'subdomain_scan', 'icmp_scan', 
                         'pma_scan', 'dir_scan', 'viewdns_reverse_ip_lookup_scan',
                         'port_scan', 'CCS_injection_vuln', 'ssl_certificate_expired_vuln', 
                         'heartbleed_vuln', 'weak_signature_algorithm_vuln', 
                         'wordpress_dos_cve_2018_6389_vuln', 'self_signed_certificate_vuln', 
                         'smtp_brute', 'ssh_brute', 'ftp_brute', 'telnet_brute', 'all']
  -x EXCLUDE_METHOD, --exclude EXCLUDE_METHOD
                        choose scan method to exclude ['admin_scan', 'subdomain_scan', 'icmp_scan', 
                         'pma_scan', 'dir_scan', 'viewdns_reverse_ip_lookup_scan', 
                         'port_scan', 'CCS_injection_vuln','ssl_certificate_expired_vuln',
                         'heartbleed_vuln', 'weak_signature_algorithm_vuln',
                         'wordpress_dos_cve_2018_6389_vuln', 'self_signed_certificate_vuln', 
                         'smtp_brute', 'ssh_brute', 'ftp_brute', 'telnet_brute']
  -u USERS, --usernames USERS
                        username(s) list, separate with ","
  -U USERS_LIST, --users-list USERS_LIST
                        read username(s) from file
  -p PASSWDS, --passwords PASSWDS
                        password(s) list, separate with ","
  -P PASSWDS_LIST, --passwords-list PASSWDS_LIST
                        read password(s) from file
  -g PORTS, --ports PORTS
                        port(s) list, separate with ","
  -T TIMEOUT_SEC, --timeout TIMEOUT_SEC
                        read passwords(s) from file
  -w TIME_SLEEP, --time-sleep TIME_SLEEP
                        time to sleep between each request
  -r, --range           scan all IPs in the range
  -s, --sub-domains     find and scan subdomains
  -t THREAD_NUMBER, --thread-connection THREAD_NUMBER
                        thread numbers for connections to a host
  -M THREAD_NUMBER_HOST, --thread-hostscan THREAD_NUMBER_HOST
                        thread numbers for scan hosts
  -R SOCKS_PROXY, --socks-proxy SOCKS_PROXY
                        outgoing connections proxy (socks). example socks5:
                        127.0.0.1:9050, socks://127.0.0.1:9050,
                        socks5://127.0.0.1:9050 or socks4:
                        socks4://127.0.0.1:9050, authentication:
                        socks://username:password@127.0.0.1,
                        socks4://username:password@127.0.0.1,
                        socks5://username:password@127.0.0.1
  --retries RETRIES     Retries when the connection timeout (default 3)
  --ping-before-scan    ping before scan the host
  --method-args METHODS_ARGS
                        enter methods inputs, example: "ftp_brute_users=test,a
                        dmin&ftp_brute_passwds=read_from_file:/tmp/pass.txt&ft
                        p_brute_port=21"
  --method-args-list    list all methods args

API:
  API options

  --start-api           start the API service
  --api-host API_HOST   API host address
  --api-port API_PORT   API port number
  --api-debug-mode      API debug mode
  --api-access-key API_ACCESS_KEY
                        API access key
  --api-client-white-list
                        just allow white list hosts to connect to the API
  --api-client-white-list-ips API_CLIENT_WHITE_LIST_IPS
                        define white list hosts, separate with "," (examples:
                        127.0.0.1, 192.168.0.1/24, 10.0.0.1-10.0.0.255)
  --api-access-log      generate API access log
  --api-access-log-filename API_ACCESS_LOG_FILENAME
                        API access log filename


Please read license and agreements https://github.com/viraintel/OWASP-Nettacker
```

* ***IoT Scanner***
*	Python Multi Thread & Multi Process Network Information Gathering Vulnerability Scanner
*	Service and Device Detection ( SCADA, Restricted Areas, Routers, HTTP Servers, Logins and Authentications, None-Indexed HTTP, Paradox System, Cameras, Firewalls, UTM, WebMails, VPN, RDP, SSH, FTP, TELNET Services, Proxy Servers and Many Devices like Juniper, Cisco, Switches and many more… ) 
*	Network Service Analysis
*	Services Brute Force Testing
*	Services Vulnerability Testing
*	HTTP/HTTPS Crawling, Fuzzing, Information Gathering and … 
*	HTML and Text Outputs
*	This project is at the moment in research and development phase and most of results/codes are not published yet.
