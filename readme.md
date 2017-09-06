Nettacker
=========
[![Build Status Travic CI](https://travis-ci.org/viraintel/OWASP-Nettacker.svg?branch=master)](https://travis-ci.org/viraintel/OWASP-Nettacker)
[![Python 2.x](https://img.shields.io/badge/python-2.x-blue.svg)](https://travis-ci.org/viraintel/OWASP-Nettacker)
[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://travis-ci.org/viraintel/OWASP-Nettacker)
[![Apache License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://github.com/viraintel/OWASP-Nettacker/blob/master/LICENSE)


***THIS SOFTWARE WAS CREATED TO AUTOMATED PENETRATION TESTING AND INFORMATION GATHERING. CONTRIBUTORS WILL NOT BE RESPONSIBLE FOR ANY ILLEGAL USAGE.***


Nettacker project was created to automated for information gathering, vulnerability scanning and eventually generating a report for networks, including services, bugs, vulnerabilities, misconfigurations and information. This software is able to use SYN, ACK, TCP, ICMP and many other protocols to detect and bypass the Firewalls/IDS/IPS and devices. By using a unique solution in Nettacker to find protected services such as SCADA We could make a point to be one of the bests of scanners.  

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



Usage: python nettacker.py [options]

Nettacker Help Menu

Options:
  -h, --help            show this help message and exit

  Engine:
    Engine input options

    -L LANGUAGE, --language=LANGUAGE
                        select a language ['fa', 'en']
    -v VERBOSE_LEVEL, --verbose=VERBOSE_LEVEL
                        verbose mode level (0-5) (default 0)
    -V, --version       show software version
    -c, --update        check for update
    -o LOG_IN_FILE, --output=LOG_IN_FILE
                        save all logs in file (results.txt, results.html)
    --graph=GRAPH_FLAG  build a graph of all activities and information, you
                        must use html output. available graphs:
                        ['d3_tree_v1_graph', 'd3_tree_v2_graph',
                        'jit_circle_v1_graph']

  Target:
    Target input options

    -i TARGETS, --targets=TARGETS
                        target(s) list, separate with ","
    -l TARGETS_LIST, --targets-list=TARGETS_LIST
                        read target(s) from file

  Method:
    Scan method options

    -m SCAN_METHOD, --method=SCAN_METHOD
                        choose scan method ['ftp_brute', 'smtp_brute',
                        'ssh_brute', 'port_scan', 'all']
    -x EXCLUDE_METHOD, --exclude=EXCLUDE_METHOD
                        choose scan method to exclude ['ftp_brute',
                        'smtp_brute', 'ssh_brute', 'port_scan']
    -u USERS, --usernames=USERS
                        username(s) list, separate with ","
    -U USERS_LIST, --users-list=USERS_LIST
                        read username(s) from file
    -p PASSWDS, --passwords=PASSWDS
                        password(s) list, separate with ","
    -P PASSWDS_LIST, --passwords-list=PASSWDS_LIST
                        read passwords(s) from file
    -g PORTS, --ports=PORTS
                        port(s) list, separate with ","
    -T TIMEOUT_SEC, --timeout=TIMEOUT_SEC
                        read passwords(s) from file
    -w TIME_SLEEP, --time-sleep=TIME_SLEEP
                        time to sleep between each request
    -r, --range         scan all IPs in range
    -s, --sub-domains   find and scan subdomains
    -t THREAD_NUMBER, --thread-connection=THREAD_NUMBER
                        thread numbers for connections to a host
    -M THREAD_NUMBER_HOST, --thread-hostscan=THREAD_NUMBER_HOST
                        thread numbers for scan hosts
    -R PROXIES, --proxy=PROXIES
                        proxy(s) list, separate with "," (out going
                        connections)
    --proxy-list=PROXIES_FILE
                        read proxies from file (out going connections)
    --retries=RETRIES   Retries when the connection timeout (default 3)

Please read license and agreements https://github.com/Nettacker/Nettacker
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
