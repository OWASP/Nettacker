Nettacker
=========

***THIS SOFTWARE WAS CREATED TO AUTOMATED PENETRATION TESTING AND INFORMATION GATHERING. CONTRIBUTORS WILL NOT BE RESPONSIBLE FOR ANY ILLEGAL USAGE.***


Nettacker project was created to automated for information gathering, vulnerability scanning and eventually generating report for networks, including services, bugs, vulnerabilities, misconfigurations and information. This software is able to use SYN, ACK, TCP, ICMP and many other protocols to detect and bypass the Firewalls/IDS/IPS and devices. By using a unique solution in Nettacker to find protected services such as SCADA We could make a point to be one of the bests of scanners, and be a good competitor of Nmap scanner but I also preparing a .nse module for make users able to use Nmap instead of Nettacker python version.  

```
python nettacker.py -h


Usage: python nettacker.py [options]

Nettacker Help Menu

Options:
  -h, --help            show this help message and exit
  -r, --range           scan all IPs in range
  -s, --sub-domains     find and scan subdomains
  -t THREAD_NUMBER, --thread-connection=THREAD_NUMBER
                        thread numbers for connections to a host
  -M THREAD_NUMBER_HOST, --thread-hostscan=THREAD_NUMBER_HOST
                        thread numbers for scan hosts
  -o LOG_IN_FILE, --output=LOG_IN_FILE
                        save all logs in file (results.txt, results.html)

  Target:
    Target input options

    -i TARGETS, --targets=TARGETS
                        target(s) list, separate with ","
    -l TARGETS_LIST, --targets-list=TARGETS_LIST
                        read target(s) from file

  Method:
    Scan method options

    -m SCAN_METHOD, --method=SCAN_METHOD
                        choose scan method ['ftp_brute', 'http_brute',
                        'smtp_brute', 'ssh_brute', 'port_scan']
    -x EXCLUDE_METHOD, --exclude=EXCLUDE_METHOD
                        choose scan method to exclude ['ftp_brute',
                        'http_brute', 'smtp_brute', 'ssh_brute', 'port_scan']
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

  Method:
    Scan method options

    -m SCAN_METHOD, --method=SCAN_METHOD
                        choose scan method ['ftp_brute', 'http_brute',
                        'smtp_brute', 'ssh_brute', 'port_scan']
    -x EXCLUDE_METHOD, --exclude=EXCLUDE_METHOD
                        choose scan method to exclude ['ftp_brute',
                        'http_brute', 'smtp_brute', 'ssh_brute', 'port_scan']
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

Please read license and agreements https://github.com/Nettacker/Nettacker

C:\Users\Bingo\Documents\GitHub\Nettacker>

C:\Users\Bingo\Documents\GitHub\Nettacker>

C:\Users\Bingo\Documents\GitHub\Nettacker>python nettacker.py -h


Usage: python nettacker.py [options]

Nettacker Help Menu

Options:
  -h, --help            show this help message and exit
  -r, --range           scan all IPs in range
  -s, --sub-domains     find and scan subdomains
  -t THREAD_NUMBER, --thread-connection=THREAD_NUMBER
                        thread numbers for connections to a host
  -M THREAD_NUMBER_HOST, --thread-hostscan=THREAD_NUMBER_HOST
                        thread numbers for scan hosts
  -o LOG_IN_FILE, --output=LOG_IN_FILE
                        save all logs in file (results.txt, results.html)

  Target:
    Target input options

    -i TARGETS, --targets=TARGETS
                        target(s) list, separate with ","
    -l TARGETS_LIST, --targets-list=TARGETS_LIST
                        read target(s) from file

  Method:
    Scan method options

    -m SCAN_METHOD, --method=SCAN_METHOD
                        choose scan method ['ftp_brute', 'http_brute',
                        'smtp_brute', 'ssh_brute', 'port_scan']
    -x EXCLUDE_METHOD, --exclude=EXCLUDE_METHOD
                        choose scan method to exclude ['ftp_brute',
                        'http_brute', 'smtp_brute', 'ssh_brute', 'port_scan']
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

  Method:
    Scan method options

    -m SCAN_METHOD, --method=SCAN_METHOD
                        choose scan method ['ftp_brute', 'http_brute',
                        'smtp_brute', 'ssh_brute', 'port_scan']
    -x EXCLUDE_METHOD, --exclude=EXCLUDE_METHOD
                        choose scan method to exclude ['ftp_brute',
                        'http_brute', 'smtp_brute', 'ssh_brute', 'port_scan']
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

Please read license and agreements https://github.com/Nettacker/Nettacker
```

* ***IoT Scanner***
*	Python Multi Thread & Multi Process Network Information Gathering Vulnerability Scanner
*	Service and Device Detection ( SCADA, Restricted Areas, Routers, HTTP Servers, Logins and Authentications, None-Indexed HTTP, Paradox System, Cameras, Firewalls, UTM, WebMails, VPN, RDP, SSH, FTP, TELNET Services, Proxy Servers and Many Devices like Juniper, Cisco, Switches and many more… ) 
*	Network Service Analysis
*	Services Brute Force Testing
*	Services Vulnerability Testing
*	HTTP/HTTPS Crawling, Fuzzing, Information Gathering and … 
*	Python and Nmap Module Version [ .nse Lua language ]
*	HTML and Text Outputs
*	This project is at the moment in research and development phase and most of results/codes are not published yet.
