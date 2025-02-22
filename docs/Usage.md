# Help Menu

- [Target inputs Option](#target-inputs-option)
  * [Command Examples](#command-examples)
- [API and WebUI](#api-and-webui)
  * [API Options](#api-options)
  * [API Examples](#api-examples)
- [Database](#database)
  * [SQLite configuration](#sqlite-configuration)
  * [MySQL configuration](#mysql-configuration)
- [Nettacker User-Agent](#nettacker-user-agent)
- [Maltego Transforms](#maltego-transforms)

By using the `--help`/`-h` switch you can read the help menu in the CLI:
 `nettacker --help`



* Note: The examples in the section of the doumentation may not reflect the latest version.

```
   ______          __      _____ _____
  / __ \ \        / /\    / ____|  __ \
 | |  | \ \  /\  / /  \  | (___ | |__) |
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/
 | |__| | \  /\  / ____ \ ____) | |     Version 0.4.1
  \____/   \/  \/_/    \_\_____/|_|     QUIN
                          _   _      _   _             _
                         | \ | |    | | | |           | |
  github.com/OWASP       |  \| | ___| |_| |_ __ _  ___| | _____ _ __
  owasp.org              | . ` |/ _ \ __| __/ _` |/ __| |/ / _ \ '__|
  z3r0d4y.com            | |\  |  __/ |_| || (_| | (__|   <  __/ |
                         |_| \_|\___|\__|\__\__,_|\___|_|\_\___|_|

[2024-09-26 07:51:08][+] Nettacker engine started ...
[2024-09-26 07:51:09][+] 106 modules loaded ...
usage: Nettacker [-L LANGUAGE] [-v] [--verbose-event] [-V] [-o REPORT_PATH_FILENAME] [--graph GRAPH_NAME] [-h]
                 [-i TARGETS] [-l TARGETS_LIST] [-m SELECTED_MODULES] [--modules-extra-args MODULES_EXTRA_ARGS]
                 [--show-all-modules] [--profile PROFILES] [--show-all-profiles] [-x EXCLUDED_MODULES] [-u USERNAMES]
                 [-U USERNAMES_LIST] [-p PASSWORDS] [-P PASSWORDS_LIST] [-g PORTS] [--user-agent USER_AGENT]
                 [-T TIMEOUT] [-w TIME_SLEEP_BETWEEN_REQUESTS] [-r] [-s] [-d] [-t THREAD_PER_HOST]
                 [-M PARALLEL_MODULE_SCAN] [--set-hardware-usage SET_HARDWARE_USAGE] [-R SOCKS_PROXY]
                 [--retries RETRIES] [--ping-before-scan] [-K SCAN_COMPARE_ID] [-J COMPARE_REPORT_PATH_FILENAME]
                 [--start-api] [--api-host API_HOSTNAME] [--api-port API_PORT] [--api-debug-mode]
                 [--api-access-key API_ACCESS_KEY] [--api-client-whitelisted-ips API_CLIENT_WHITELISTED_IPS]
                 [--api-access-log API_ACCESS_LOG] [--api-cert API_CERT] [--api-cert-key API_CERT_KEY]

Engine:
  Engine input options

  -L LANGUAGE, --language LANGUAGE
                        select a language ['iw', 'nl', 'es', 'ru', 'de', 'ur', 'pt-br', 'fr', 'el', 'hy', 'ko', 'en',
                        'ja', 'bn', 'it', 'tr', 'ar', 'zh-cn', 'hi', 'vi', 'id', 'fa', 'ps']
  -v, --verbose         verbose mode level (0-5) (default 0)
  --verbose-event       enable verbose event to see state of each thread
  -V, --version         show software version
  -o REPORT_PATH_FILENAME, --output REPORT_PATH_FILENAME
                        save all logs in file (results.txt, results.csv, results.html, results.json)
  --graph GRAPH_NAME    build a graph of all activities and information, you must use HTML output. available graphs:
                        ['d3_tree_v2_graph', 'd3_tree_v1_graph']
  -h, --help            Show Nettacker Help Menu

Target:
  Target input options

  -i TARGETS, --targets TARGETS
                        target(s) list, separate with ","
  -l TARGETS_LIST, --targets-list TARGETS_LIST
                        read target(s) from file

Method:
  Scan method options

  -m SELECTED_MODULES, --modules SELECTED_MODULES
                        choose modules ['accela_cve_2021_34370_vuln', 'admin_scan',
                        'adobe_coldfusion_cve_2023_26360_vuln', 'apache_cve_2021_41773_vuln',
                        'apache_cve_2021_42013_vuln', 'apache_ofbiz_cve_2024_38856_vuln', 'apache_struts_vuln',
                        'aviatrix_cve_2021_40870_vuln', 'cisco_hyperflex_cve_2021_1497_vuln',
                        'citrix_cve_2019_19781_vuln'] to see full list use --show-all-modules
  --modules-extra-args MODULES_EXTRA_ARGS
                        add extra args to pass to modules (e.g. --modules-extra-args "x_api_key=123&xyz_passwd=abc"
  --show-all-modules    show all modules and their information
  --profile PROFILES    select profile ['accela', 'adobe', 'apache', 'apache_ofbiz', 'apache_struts', 'atlassian',
                        'aviatrix', 'backup', 'brute', 'brute_force']
  --show-all-profiles   show all profiles and their information
  -x EXCLUDED_MODULES, --exclude-modules EXCLUDED_MODULES
                        choose scan method to exclude ['accela_cve_2021_34370_vuln', 'admin_scan',
                        'adobe_coldfusion_cve_2023_26360_vuln', 'apache_cve_2021_41773_vuln',
                        'apache_cve_2021_42013_vuln', 'apache_ofbiz_cve_2024_38856_vuln', 'apache_struts_vuln',
                        'aviatrix_cve_2021_40870_vuln', 'cisco_hyperflex_cve_2021_1497_vuln']
  -u USERNAMES, --usernames USERNAMES
                        username(s) list, separate with ","
  -U USERNAMES_LIST, --users-list USERNAMES_LIST
                        read username(s) from file
  -p PASSWORDS, --passwords PASSWORDS
                        password(s) list, separate with ","
  -P PASSWORDS_LIST, --passwords-list PASSWORDS_LIST
                        read password(s) from file
  -g PORTS, --ports PORTS
                        port(s) list, separate with ","
  --user-agent USER_AGENT
                        Select a user agent to send with HTTP requests or enter "random_user_agent" to randomize the
                        User-Agent in the requests.
  -T TIMEOUT, --timeout TIMEOUT
                        read password(s) from file
  -w TIME_SLEEP_BETWEEN_REQUESTS, --time-sleep-between-requests TIME_SLEEP_BETWEEN_REQUESTS
                        time to sleep between each request
  -r, --range           scan all IPs in the range
  -s, --sub-domains     find and scan subdomains
  -d, --skip-service-discovery
                        skip service discovery before scan and enforce all modules to scan anyway
  -t THREAD_PER_HOST, --thread-per-host THREAD_PER_HOST
                        thread numbers for connections to a host
  -M PARALLEL_MODULE_SCAN, --parallel-module-scan PARALLEL_MODULE_SCAN
                        parallel module scan for hosts
  --set-hardware-usage SET_HARDWARE_USAGE
                        Set hardware usage while scanning. (low, normal, high, maximum)
  -R SOCKS_PROXY, --socks-proxy SOCKS_PROXY
                        outgoing connections proxy (socks). example socks5: 127.0.0.1:9050, socks://127.0.0.1:9050
                        socks5://127.0.0.1:9050 or socks4: socks4://127.0.0.1:9050, authentication: socks://username:
                        password@127.0.0.1, socks4://username:password@127.0.0.1, socks5://username:password@127.0.0.1
  --retries RETRIES     Retries when the connection timeout (default 3)
  --ping-before-scan    ping before scan the host
  -K SCAN_COMPARE_ID, --scan-compare SCAN_COMPARE_ID
                        compare current scan to old scans using the unique scan_id
  -J COMPARE_REPORT_PATH_FILENAME, --compare-report-path COMPARE_REPORT_PATH_FILENAME
                        the file-path to store the compare_scan report

API:
  API options

  --start-api           start the API service
  --api-host API_HOSTNAME
                        API host address
  --api-port API_PORT   API port number
  --api-debug-mode      API debug mode
  --api-access-key API_ACCESS_KEY
                        API access key
  --api-client-whitelisted-ips API_CLIENT_WHITELISTED_IPS
                        define white list hosts, separate with , (examples: 127.0.0.1, 192.168.0.1/24,
                        10.0.0.1-10.0.0.255)
  --api-access-log API_ACCESS_LOG
                        API access log filename
  --api-cert API_CERT   API CERTIFICATE
  --api-cert-key API_CERT_KEY
                        API CERTIFICATE Key


Please read license and agreements https://github.com/OWASP/Nettacker%
```

## Language Selection

Nettacker supports multiple languages for its output, allowing users to select the language they prefer. To specify a language, use the -L flag followed by the appropriate language code.

For example, to set the output language to Farsi, run: 
`$ nettacker -L fa`

In this example, the -L flag is used to select the language, and `fa` indicates Farsi.

Nettacker supports the following languages:

* Arabic ('ar')
* Armenian ('hy')
* Bengali ('bn')
* Dutch ('nl')
* English ('en')
* Farsi ('fa')
* French ('fr')
* German ('de')
* Greek ('el')
* Hebrew ('iw')
* Hindi ('hi')
* Indonesian ('id')
* Italian ('it')
* Japanese ('ja')
* Korean ('ko')
* Pashto ('ps')
* Portuguese (Brazil) ('pt-br')
* Russian ('ru')
* Simplified Chinese ('zh-cn')
* Spanish ('es')
* Turkish ('tr')
* Urdu ('ur')
* Vietnamese ('vi')

For a complete list of available languages, you can refer to the command line help.

* Your CLI must support Unicode to make use of multiple languages. Search the web for "How to use Farsi on cmd/terminal."
* You can fix Persian (Farsi) and other Unicode languages RTL and Chars with [bicon](https://www.google.com/search?q=Persian+support+with+bicon&oq=Persian+support+with+bicon&aqs=chrome..69i57.178j0j7&sourceid=chrome&ie=UTF-8) in terminal/windows bash.
```
$ nettacker --help -L fa
   ______          __      _____ _____
  / __ \ \        / /\    / ____|  __ \
 | |  | \ \  /\  / /  \  | (___ | |__) |
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/
 | |__| | \  /\  / ____ \ ____) | |     Version 0.4.1
  \____/   \/  \/_/    \_\_____/|_|     QUIN
                          _   _      _   _             _
                         | \ | |    | | | |           | |
  github.com/OWASP       |  \| | ___| |_| |_ __ _  ___| | _____ _ __
  owasp.org              | . ` |/ _ \ __| __/ _` |/ __| |/ / _ \ '__|
  z3r0d4y.com            | |\  |  __/ |_| || (_| | (__|   <  __/ |
                         |_| \_|\___|\__|\__\__,_|\___|_|\_\___|_|

[2024-09-26 07:53:24][+] انجین Nettacker آغاز به کار کرد ...


[2024-09-26 07:53:25][+] 106 ماژول بارگزاری شد ...
usage: Nettacker [-L LANGUAGE] [-v] [--verbose-event] [-V] [-o REPORT_PATH_FILENAME] [--graph GRAPH_NAME] [-h]
                 [-i TARGETS] [-l TARGETS_LIST] [-m SELECTED_MODULES] [--modules-extra-args MODULES_EXTRA_ARGS]
                 [--show-all-modules] [--profile PROFILES] [--show-all-profiles] [-x EXCLUDED_MODULES] [-u USERNAMES]
                 [-U USERNAMES_LIST] [-p PASSWORDS] [-P PASSWORDS_LIST] [-g PORTS] [--user-agent USER_AGENT]
                 [-T TIMEOUT] [-w TIME_SLEEP_BETWEEN_REQUESTS] [-r] [-s] [-d] [-t THREAD_PER_HOST]
                 [-M PARALLEL_MODULE_SCAN] [--set-hardware-usage SET_HARDWARE_USAGE] [-R SOCKS_PROXY]
                 [--retries RETRIES] [--ping-before-scan] [-K SCAN_COMPARE_ID] [-J COMPARE_REPORT_PATH_FILENAME]
                 [--start-api] [--api-host API_HOSTNAME] [--api-port API_PORT] [--api-debug-mode]
                 [--api-access-key API_ACCESS_KEY] [--api-client-whitelisted-ips API_CLIENT_WHITELISTED_IPS]
                 [--api-access-log API_ACCESS_LOG] [--api-cert API_CERT] [--api-cert-key API_CERT_KEY]

انجین:
  گزینه های ورودی انجین

  -L LANGUAGE, --language LANGUAGE
                        یک زبان انتخاب کنید ['bn', 'de', 'nl', 'iw', 'es', 'pt-br', 'ar', 'tr', 'el', 'ko', 'ru', 'hi',
                        'it', 'en', 'fr', 'id', 'ps', 'ur', 'zh-cn', 'hy', 'fa', 'ja', 'vi']
  -v, --verbose         سطح حالت پرگویی (0-5) (پیشفرض 0)
  --verbose-event       enable verbose event to see state of each thread
  -V, --version         نمایش ورژن نرم افزار
  -o REPORT_PATH_FILENAME, --output REPORT_PATH_FILENAME
                        ذخیره کردن کل لاگ ها در فایل (result.txt، result.html، results.json)
  --graph GRAPH_NAME    ساخت گراف از همه فعالیت ها و اطلاعات، شما باید از خروجی HTML استفاده کنید. گراف های در دسترس:
                        ['d3_tree_v1_graph', 'd3_tree_v2_graph']
  -h, --help            نشان دادن منوی کمک Nettacker

هدف:
  گزینه های ورودی هدف

  -i TARGETS, --targets TARGETS
                        لیست هدف (ها)، با "," جدا کنید
  -l TARGETS_LIST, --targets-list TARGETS_LIST
                        خواندن هدف (ها) از فایل

متود:
  گزینه های متود های اسکن

  -m SELECTED_MODULES, --modules SELECTED_MODULES
                        متود اسکن را انتخاب کنید ['accela_cve_2021_34370_vuln', 'admin_scan',
                        'adobe_coldfusion_cve_2023_26360_vuln', 'apache_cve_2021_41773_vuln',
                        'apache_cve_2021_42013_vuln', 'apache_ofbiz_cve_2024_38856_vuln', 'apache_struts_vuln',
                        'aviatrix_cve_2021_40870_vuln', 'cisco_hyperflex_cve_2021_1497_vuln',
                        'citrix_cve_2019_19781_vuln']
  --modules-extra-args MODULES_EXTRA_ARGS
                        add extra args to pass to modules (e.g. --modules-extra-args "x_api_key=123&xyz_passwd=abc"
  --show-all-modules    show all modules and their information
  --profile PROFILES    انتخاب پروفایل ['accela', 'adobe', 'apache', 'apache_ofbiz', 'apache_struts', 'atlassian',
                        'aviatrix', 'backup', 'brute', 'brute_force']
  --show-all-profiles   show all profiles and their information
  -x EXCLUDED_MODULES, --exclude-modules EXCLUDED_MODULES
                        انتخاب متود اسکن استثنا ['accela_cve_2021_34370_vuln', 'admin_scan',
                        'adobe_coldfusion_cve_2023_26360_vuln', 'apache_cve_2021_41773_vuln',
                        'apache_cve_2021_42013_vuln', 'apache_ofbiz_cve_2024_38856_vuln', 'apache_struts_vuln',
                        'aviatrix_cve_2021_40870_vuln', 'cisco_hyperflex_cve_2021_1497_vuln']
  -u USERNAMES, --usernames USERNAMES
                        لیست نام کاربری (ها)، با "," جدا شود
  -U USERNAMES_LIST, --users-list USERNAMES_LIST
                        خواندن نام کاربری (ها) از لیست
  -p PASSWORDS, --passwords PASSWORDS
                        لیست کلمه عبور (ها)، با "," جدا شود
  -P PASSWORDS_LIST, --passwords-list PASSWORDS_LIST
                        خواندن کلمه عبور (ها) از فایل
  -g PORTS, --ports PORTS
                        لیست درگاه (ها)، با "," جدا شود
  --user-agent USER_AGENT
                        Select a user agent to send with HTTP requests or enter "random_user_agent" to randomize the
                        User-Agent in the requests.
  -T TIMEOUT, --timeout TIMEOUT
                        خواندن کلمه عبور (ها) از فایل
  -w TIME_SLEEP_BETWEEN_REQUESTS, --time-sleep-between-requests TIME_SLEEP_BETWEEN_REQUESTS
                        زمان مکث بین هر درخواست
  -r, --range           اسکن تمام آی پی ها در رنج
  -s, --sub-domains     پیدا کردن و اسکن کردن ساب دامین ها
  -d, --skip-service-discovery
                        skip service discovery before scan and enforce all modules to scan anyway
  -t THREAD_PER_HOST, --thread-per-host THREAD_PER_HOST
                        تعداد ریسه ها برای ارتباطات با یک هاست
  -M PARALLEL_MODULE_SCAN, --parallel-module-scan PARALLEL_MODULE_SCAN
                        parallel module scan for hosts
  --set-hardware-usage SET_HARDWARE_USAGE
                        Set hardware usage while scanning. (low, normal, high, maximum)
  -R SOCKS_PROXY, --socks-proxy SOCKS_PROXY
                        پراکسی ارتباطات خروجی (socks) مثال: 127.0.0.1:9050، socks://127.0.0.1:9050،
                        socks5:127.0.0.1:9050 یا socks4: socks4://127.0.0.1:9050, احراز هویت:
                        socks://username:password@127.0.0.1, socks4://username:password@127.0.0.1,
                        socks5://username:password@127.0.0.1
  --retries RETRIES     سعی مجدد وقتی که ارتباط قطع شد (پیشفرض 3)
  --ping-before-scan    پینگ کردن هست قبل از اسکن
  -K SCAN_COMPARE_ID, --scan-compare SCAN_COMPARE_ID
                        compare current scan to old scans using the unique scan_id
  -J COMPARE_REPORT_PATH_FILENAME, --compare-report-path COMPARE_REPORT_PATH_FILENAME
                        the file-path to store the compare_scan report

API:
  API گزینه های

  --start-api           شروع سرویس API
  --api-host API_HOSTNAME
                        آدرس هاست API
  --api-port API_PORT   شماره درگاه API
  --api-debug-mode      حالت اشکال زدایی API
  --api-access-key API_ACCESS_KEY
                        کلید دسترسی API
  --api-client-whitelisted-ips API_CLIENT_WHITELISTED_IPS
                        تعریف کردن لیست سفید، با "," جدا کنید (مثال: 127.0.0.1, 192.168.1.1/24, 10.0.0.1-10.0.0.255)
  --api-access-log API_ACCESS_LOG
                        اسم فایل لیست دسترسی به API
  --api-cert API_CERT   API CERTIFICATE
  --api-cert-key API_CERT_KEY
                        API CERTIFICATE Key


لطفا مجوز و موافقت نامه را مطالعه فرمایید https://github.com/OWASP/Nettacker
```

***

# Target inputs Option

* OWASP Nettacker supports several types of targets, including `IPv4`, `IPv4_Range`, `IPv4_CIDR`, `DOMAIN`, and `HTTP` (which may be useful for some of the modules).

## Command Examples
```
192.168.1.1
192.168.1.1-192.168.255.255
192.168.1.1.1-192.255.255.255
192.168.1.1/24
owasp.org
http://owasp.org
https://owasp.org
```

* Targets can be read from a list by using the `-l` or `--target-list` command or you can split them with a comma if you don't want to use a text list.

```
nettacker -i 192.168.1.1,192.168.1.2-192.168.1.10,127.0.0.1,owasp.org,192.168.2.1/24 -m port_scan -g 20-100 -t 10
nettacker -l targets.txt -m all -x port_scan -g 20-100 -t 5 -u root -p 123456,654321,123123
```

* Here are some more command line examples:
```
nettacker -i 192.168.1.1/24 -m port_scan -t 10 -M 35 -g 20-100 --graph d3_tree_v2_graph -o result.html
nettacker -i 192.168.1.1/24 -m port_scan -t 10 -M 35 -g 20-100 -o file.html --graph jit_circle_v1_graph
nettacker -i 192.168.1.1/24 -m all -t 10 -M 35 -g 20-100 -o result.json -u root,user -P passwords.txt
nettacker -i 192.168.1.1/24 -m all -x ssh_brute -t 10 -M 35 -g 20-100 -o file.txt -U users.txt -P passwords.txt -T 3 -w 2
```

* Using Whatcms Scan: API key can be found [here](https://whatcms.org/APIKey)
```
nettacker -i eng.uber.com -m whatcms_scan --method-args whatcms_api_key=XXXX
```
* Finding CVE 2020-5902:
```
nettacker -i <CIDR/IP/Domain> -m f5_cve_2020_5902
nettacker -l <List of IP/CIDR/Domain> -m f5_cve_2020_5902
nettacker -i <CIDR/IP/Domain> -m f5_cve_2020_5902 -s
```

* OWASP Nettacker can also scan subdomains by using this command: `-s`

```
nettacker -i owasp.org -s -m port_scan -t 10 -M 35 -g 20-100 --graph d3_tree_v2_graph
```

* If you use `-r` command, it will scan the IP range automatically by getting the range from the RIPE database online.
```
nettacker -i owasp.org -s -r -m port_scan -t 10 -M 35 -g 20-100 --graph d3_tree_v2_graph
nettacker -i nettackerwebsiteblabla.com,owasp.org,192.168.1.1 -s -r -m all -t 10 -M 35 -g 20-100 -o file.txt -u root,user -P passwords.txt
```

* Note: If host scan finishes, and couldn't get any result nothing will be listed in the output file unless you change the verbosity mode to a value from 1 to 5.

```
nettacker -i 192.168.1.1/24 -m all -t 10 -M 35 -g 20-100 -o file.txt -u root,user -P passwords.txt -v 1
```


* Use profiles for using all modules inside a given profile

```
nettacker -i 192.168.1.1/24 --profile information_gathering
nettacker -i 192.168.1.1/24 --profile information_gathering,vulnerabilities
nettacker -i 192.168.1.1/24 --profile all
```

![](https://user-images.githubusercontent.com/24669027/39022564-bf96bde2-4453-11e8-9814-c30db364aa4d.gif)


* Use socks proxy for outgoing connections (default socks version is 5)
```
nettacker -i 192.168.1.1 -m port_scan -T 5 --socks-proxy socks://127.0.0.1:9050
nettacker -i 192.168.1.1 -m port_scan -T 5 --socks-proxy socks4://127.0.0.1:9050
nettacker -i 192.168.1.1 -m port_scan -T 5 --socks-proxy socks5://127.0.0.1:9050
nettacker -i 192.168.1.1 -m port_scan -T 5 --socks-proxy socks://username:password@127.0.0.1:9050
nettacker -i 192.168.1.1 -m port_scan -T 5 --socks-proxy socks4://username:password@127.0.0.1:9050
nettacker -i 192.168.1.1 -m port_scan -T 5 --socks-proxy socks5://username:password@127.0.0.1:9050
```

* Get the list of all modules with details about it using `--show-all-modules`
```
nettacker --show-all-modules
   ______          __      _____ _____
  / __ \ \        / /\    / ____|  __ \
 | |  | \ \  /\  / /  \  | (___ | |__) |
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/
 | |__| | \  /\  / ____ \ ____) | |     Version 0.4.0
  \____/   \/  \/_/    \_\_____/|_|     QUIN
                          _   _      _   _             _
                         | \ | |    | | | |           | |
  github.com/OWASP       |  \| | ___| |_| |_ __ _  ___| | _____ _ __
  owasp.org              | . ` |/ _ \ __| __/ _` |/ __| |/ / _ \ '__|
  z3r0d4y.com            | |\  |  __/ |_| || (_| | (__|   <  __/ |
                         |_| \_|\___|\__|\__\__,_|\___|_|\_\___|_|

[2025-02-22 01:28:17][+] Nettacker engine started ...
[2025-02-22 01:28:18][+] 107 modules loaded ...
[2025-02-22 01:28:19][+] loading all modules... it might get some time!
[2025-02-22 01:28:19][+] accela_cve_2021_34370_vuln: name: accela_cve_2021_34370_vuln, author: OWASP Nettacker Team, severity: 6, description: Accela Civic Platform Cross-Site-Scripting and Open Redirect <= 21.1, reference: ['https://www.exploit-db.com/exploits/49990', 'https://nvd.nist.gov/vuln/detail/CVE-2021-34370'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve2021', 'cve', 'accela', 'open_redirect']
[2025-02-22 01:28:19][+] admin_scan: name: admin_scan, author: OWASP Nettacker Team, severity: 3, description: Admin Directory Finder, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity']
[2025-02-22 01:28:19][+] adobe_coldfusion_cve_2023_26360_vuln: name: adobe_coldfusion_cve_2023_26360_vuln, author: Jimmy Ly, severity: 9.8, description: CVE-2023-26360 - Unauthenticated deserialization of untrusted data vulnerability in Adobe ColdFusion 2021 Update 5 and earlier as well as ColdFusion 2018 Update 15 and earlier, in order to gain unauthenticated arbitrary file read and remote code execution., reference: ['https://nvd.nist.gov/vuln/detail/CVE-2023-26360', 'https://helpx.adobe.com/security/products/coldfusion/apsb23-25.html', 'http://packetstormsecurity.com/files/172079/Adobe-ColdFusion-Unauthenticated-Remote-Code-Execution.html'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve', 'adobe', 'coldfusion']
[2025-02-22 01:28:19][+] apache_cve_2021_41773_vuln: name: apache_cve_2021_41773_vuln, author: OWASP Nettacker Team, severity: 9, description: A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by "require all denied" these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions., reference: ['https://github.com/apache/httpd/commit/e150697086e70c552b2588f369f2d17815cb1782', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve2021', 'cve', 'apache', 'path_traversal', 'lfi']
[2025-02-22 01:28:19][+] apache_cve_2021_42013_vuln: name: apache_cve_2021_42013_vuln, author: OWASP Nettacker Team, severity: 9, description: A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by "require all denied" these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions., reference: ['https://github.com/apache/httpd/commit/5c385f2b6c8352e2ca0665e66af022d6e936db6d', 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve2021', 'cve', 'apache', 'path_traversal', 'lfi']
[2025-02-22 01:28:19][+] apache_ofbiz_cve_2024_38856_vuln: name: apache_ofbiz_cve_2024_38856_vuln, author: OWASP Nettacker Team, severity: 9.8, description: CVE-2024-38856 Apache OFBiz Unauthenticated endpoint could allow execution of screen rendering code, reference: ['https://www.zscaler.com/blogs/security-research/cve-2024-38856-pre-auth-rce-vulnerability-apache-ofbiz', 'https://www.cisa.gov/news-events/alerts/2024/08/27/cisa-adds-one-known-exploited-vulnerability-catalog', 'https://issues.apache.org/jira/browse/OFBIZ-13128'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve', 'apache', 'apache_ofbiz', 'cisa_kev']
[2025-02-22 01:28:19][+] apache_struts_vuln: name: apache_struts_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity', 'apache_struts']
[2025-02-22 01:28:19][+] aviatrix_cve_2021_40870_vuln: name: aviatrix_cve_2021_40870_vuln, author: OWASP Nettacker Team, severity: 9, description: Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal., reference: ['https://wearetradecraft.com/advisories/tc-2021-0002/', 'https://nvd.nist.gov/vuln/detail/CVE-2021-40870'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve2021', 'cve', 'aviatrix', 'rce']
[2025-02-22 01:28:19][+] cisco_hyperflex_cve_2021_1497_vuln: name: cisco_hyperflex_cve_2021_1497_vuln, author: OWASP Nettacker Team, severity: 9.8, description: Multiple vulnerabilities in the web-based management interface of Cisco HyperFlex HX could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device., reference: ['https://nvd.nist.gov/vuln/detail/CVE-2021-1497', 'https://packetstormsecurity.com/files/162976/Cisco-HyperFlex-HX-Data-Platform-Command-Execution.html'], profiles: ['vuln', 'vulnerability', 'http', 'high_severity', 'cve', 'hyperflex', 'cisco']
[2025-02-22 01:28:19][+] citrix_cve_2019_19781_vuln: name: citrix_cve_2019_19781_vuln, author: OWASP Nettacker Team, severity: 8, description: CVE-2019-19781 - Vulnerability in Citrix Application Delivery Controller, Citrix Gateway, and Citrix SD-WAN WANOP appliance, reference: ['https://support.citrix.com/article/CTX267027'], profiles: ['vuln', 'vulnerability', 'http', 'high_severity', 'cve', 'citrix']
[2025-02-22 01:28:19][+] citrix_cve_2023_24488_vuln: name: citrix_cve_2023_24488_vuln, author: OWASP Nettacker Team, severity: 6, description: CVE-2023-24488 - XSS Vulnerability in Citrix Application Delivery Controller and Citrix Gateway, reference: ['https://support.citrix.com/article/CTX477714', 'https://blog.assetnote.io/2023/06/29/binary-reversing-citrix-xss/', 'https://blog.assetnote.io/2023/06/29/citrix-xss-advisory/'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve', 'citrix']
[2025-02-22 01:28:19][+] citrix_cve_2023_4966_vuln: name: citrix_cve_2023_4966_vuln, author: Jimmy Ly, severity: 9.4, description: CVE-2023-4966 - Retrieve sensitive information such as authentication session cookies in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy)., reference: ['https://support.citrix.com/article/CTX579459/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20234966-and-cve20234967', 'https://nvd.nist.gov/vuln/detail/CVE-2023-4966', 'https://www.assetnote.io/resources/research/citrix-bleed-leaking-session-tokens-with-cve-2023-4966', 'https://github.com/advisories/GHSA-2g42-2pwg-93cj'], profiles: ['vuln', 'vulnerability', 'http', 'high_severity', 'cve', 'citrix']
[2025-02-22 01:28:19][+] citrix_lastpatcheddate_scan: name: citrix_lastpatcheeddate_scan, author: OWASP Nettacker Team, severity: 3, description: Citrix Netscaler Gateway Last Patched Date Scan, reference: None, profiles: ['scan', 'http', 'citrix', 'low_severity']
[2025-02-22 01:28:19][+] clickjacking_vuln: name: clickjacking_vuln, author: OWASP Nettacker Team, severity: 5, description: Clickjacking, also known as a "UI redress attack", is when an attacker uses multiple transparent or opaque layers to trick a user into clicking on a button, reference: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html, profiles: ['vuln', 'vulnerability', 'http', 'medium_severity']
[2025-02-22 01:28:19][+] cloudron_cve_2021_40868_vuln: name: cloudron_cve_2021_40868_vuln, author: OWASP Nettacker Team, severity: 5, description: In Cloudron 6.2, the returnTo parameter on the login page is vulnerable to Reflected XSS., reference: ['https://packetstormsecurity.com/files/164255/Cloudron-6.2-Cross-Site-Scripting.html', 'https://nvd.nist.gov/vuln/detail/CVE-2021-40868'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve2021', 'cve', 'cloudron', 'xss']
[2025-02-22 01:28:19][+] confluence_cve_2023_22515_vuln: name: confluence_cve_2023_22515_vuln, author: Jimmy Ly, severity: 10, description: Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in publicly accessible Confluence Data Center and Server instances to create unauthorized Confluence administrator accounts and access Confluence instances., reference: ['https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html', 'https://attackerkb.com/topics/Q5f0ItSzw5/cve-2023-22515/rapid7-analysis', 'https://confluence.atlassian.com/kb/faq-for-cve-2023-22515-1295682188.html', 'https://jira.atlassian.com/browse/CONFSERVER-92475', 'https://www.cisa.gov/news-events/alerts/2023/10/05/cisa-adds-three-known-exploited-vulnerabilities-catalog', 'https://nvd.nist.gov/vuln/detail/CVE-2023-22515'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve', 'confluence', 'atlassian']
[2025-02-22 01:28:19][+] confluence_cve_2023_22527_vuln: name: confluence_cve_2023_22527_vuln, author: Jimmy Ly, severity: 10, description: A template injection vulnerability on out-of-date versions of Confluence Data Center and Server allows an unauthenticated attacker to achieve RCE on an affected version., reference: ['https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and-confluence-server-1333990257.html', 'https://blog.projectdiscovery.io/atlassian-confluence-ssti-remote-code-execution/', 'https://nvd.nist.gov/vuln/detail/CVE-2023-22527'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve', 'confluence', 'atlassian']
[2025-02-22 01:28:19][+] confluence_version_scan: name: confluence_version_scan, author: Jimmy Ly, severity: 3, description: Fetch Confluence version from target, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'confluence', 'atlassian']
[2025-02-22 01:28:19][+] content_security_policy_vuln: name: content_security_policy_vuln, author: OWASP Nettacker Team, severity: 3, description: Content-Security-Policy is the name of a HTTP response header that modern browsers use to enhance the security of the document (or web page). The Content-Security-Policy header allows you to restrict how resources such as JavaScript, CSS, or pretty much anything that the browser loads., reference: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html, profiles: ['vuln', 'vulnerability', 'http', 'low_severity', 'csp']
[2025-02-22 01:28:19][+] content_type_options_vuln: name: content_type_options_vuln, author: OWASP Nettacker Team, severity: 2, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2025-02-22 01:28:19][+] cyberoam_netgenie_cve_2021_38702_vuln: name: cyberoam_netgenie_cve_2021_38702_vuln, author: OWASP Nettacker Team, severity: 6, description: Cyberoam NetGenie C0101B1-20141120-NG11VO devices through 2021-08-14 allow for reflected Cross Site Scripting via the 'u' parameter of ft.php., reference: https://seclists.org/fulldisclosure/2021/Aug/20, profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve_2021_38702', 'cve2021', 'cve', 'cyberoam', 'netgenie', 'xss', 'router']
[2025-02-22 01:28:19][+] dir_scan: name: dir_scan, author: OWASP Nettacker Team, severity: 3, description: Interesting Directory Finder, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity']
[2025-02-22 01:28:19][+] drupal_modules_scan: name: drupal_module_scan, author: OWASP Nettacker Team, severity: 3, description: fetch drupal version from target, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'drupal']
[2025-02-22 01:28:19][+] drupal_theme_scan: name: drupal_theme_scan, author: OWASP Nettacker Team, severity: 3, description: fetch drupal version from target, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'drupal']
[2025-02-22 01:28:19][+] drupal_version_scan: name: drupal_version_scan, author: OWASP Nettacker Team, severity: 3, description: fetch drupal version from target, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'drupal']
[2025-02-22 01:28:19][+] exponent_cms_cve_2021_38751_vuln: name: exponent_cms_cve_2021_38751_vuln, author: OWASP Nettacker Team, severity: 5, description: A HTTP Host header attack exists in ExponentCMS 2.6 and below in /exponent_constants.php. A modified HTTP header can change links on the webpage to an arbitrary value, leading to a possible attack vector for MITM., reference: ['https://github.com/exponentcms/exponent-cms/issues/1544', 'https://github.com/exponentcms/exponent-cms/blob/a9fa9358c5e8dc2ce7ad61d7d5bea38505b8515c/exponent_constants.php#L56-L64'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve', 'exponent_cms', 'cve2021']
[2025-02-22 01:28:19][+] f5_cve_2020_5902_vuln: name: f5_cve_2020_5902_vuln, author: OWASP Nettacker Team, severity: 9, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve', 'f5']
[2025-02-22 01:28:19][+] forgerock_am_cve_2021_35464_vuln: name: forgerock_am_cve_2021_35464_vuln, author: OWASP Nettacker Team, severity: 9, description: ForgeRock AM server before 7.0 has a Java deserialization vulnerability in the jato.pageSession parameter on multiple pages. The exploitation does not require authentication, and remote code execution can be triggered by sending a single crafted /ccversion/* request to the server. The vulnerability exists due to the usage of Sun ONE Application Framework (JATO) found in versions of Java 8 or earlier, reference: ['https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve2021', 'cve', 'rce', 'openam', 'forgerock_am']
[2025-02-22 01:28:19][+] ftp_brute: name: ftp_brute, author: OWASP Nettacker Team, severity: 3, description: FTP Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'ftp']
[2025-02-22 01:28:19][+] ftps_brute: name: ftps_brute, author: OWASP Nettacker Team, severity: 3, description: FTPS Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'ftp']
[2025-02-22 01:28:19][+] galera_webtemp_cve_2021_40960_vuln: name: galera_webtemp_cve_2021_40960_vuln, author: OWASP Nettacker Team, severity: 7, description: Galera WebTemplate 1.0 is affected by a directory traversal vulnerability that could reveal information from /etc/passwd and /etc/shadow., reference: ['http://www.omrylmz.com/galera-webtemplate-1-0-directory-traversal-vulnerability-cve-2021-40960/', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40960'], profiles: ['vuln', 'vulnerability', 'http', 'high_severity', 'cve2021', 'cve', 'galera', 'lfi']
[2025-02-22 01:28:19][+] grafana_cve_2021_43798_vuln: name: grafana_cve_2021_43798_vuln, author: OWASP Nettacker Team, severity: 9, description: Grafana unpatched 0 Day LFI is now being actively exploited, it affects only Grafana 8.0+, Vulnerable companies should revoke the secrets they store at their /etc/grafana/grafana.ini as there is no official fix in the meantime., reference: ['https://nosec.org/home/detail/4914.html', 'https://github.com/jas502n/Grafana-VulnTips'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'grafana', 'lfi']
[2025-02-22 01:28:19][+] graphql_vuln: name: graphql_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'information_gathering', 'http', 'low_severity', 'graphql']
[2025-02-22 01:28:19][+] gurock_testrail_cve_2021_40875_vuln: name: gurock_testrail_cve_2021_40875_vuln, author: OWASP Nettacker Team, severity: 5, description: Improper Access Control in Gurock TestRail versions < 7.2.0.3014 resulted in sensitive information exposure. A threat actor can access the /files.md5 file on the client side of a Gurock TestRail application, disclosing a full list of application files and the corresponding file paths. The corresponding file paths can be tested, and in some cases, result in the disclosure of hardcoded credentials, API keys, or other sensitive data., reference: ['https://www.gurock.com/testrail/tour/enterprise-edition', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40875'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve2021', 'cve', 'gurock', 'gurock_testrail']
[2025-02-22 01:28:19][+] hoteldruid_cve_2021-37833_vuln: name: hoteldruid_cve_2021_37833_vuln, author: OWASP Nettacker Team, severity: 6, description: Reflected cross-site scripting (XSS) vulnerability exists in multiple pages in version 3.0.2 of the Hotel Druid application that allows for arbitrary execution of JavaScript commands., reference: ['https://github.com/dievus/CVE-2021-37833', 'https://nvd.nist.gov/vuln/detail/CVE-2021-37833'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve2021', 'cve', 'hoteldruid', 'xss']
[2025-02-22 01:28:19][+] http_cookie_vuln: name: http_cookie_vuln, author: OWASP Nettacker Team, severity: 3, description: This module check for Set-Cookie header best practices., reference: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes', 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'], profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2025-02-22 01:28:19][+] http_cors_vuln: name: http_cors_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2025-02-22 01:28:19][+] http_html_title_scan: name: http_html_title_scan, author: OWASP Nettacker Team, severity: 3, description: HTTP HTML Title scan - extracts the TITLE tag which can help identify the application running on the server, reference: None, profiles: ['scan', 'http', 'low_severity']
[2025-02-22 01:28:19][+] http_options_enabled_vuln: name: http_options_enabled_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2025-02-22 01:28:19][+] http_redirect_scan: name: http_redirect_scan, author: OWASP Nettacker Team, severity: 3, description: HTTP Redirect scan checks if a target website responds with a 3xx status code, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity']
[2025-02-22 01:28:19][+] http_status_scan: name: status_scan, author: OWASP Nettacker Team, severity: 3, description: HTTP Status scan, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity']
[2025-02-22 01:28:19][+] icmp_scan: name: icmp_scan, author: OWASP Nettacker Team, severity: 0, description: check if host is alive through ICMP, reference: None, profiles: ['scan', 'information_gathering', 'infortmation', 'info', 'low_severity']
[2025-02-22 01:28:19][+] ivanti_csa_lastpatcheddate_scan: name: ivanti_csa_lastpatcheddate_scan, author: OWASP Nettacker Team, severity: 3, description: Ivanti CSA Last Patched Date Scan, reference: https://www.bleepingcomputer.com/news/security/ivanti-warns-of-another-critical-csa-flaw-exploited-in-attacks/, profiles: ['scan', 'http', 'ivanti', 'low_severity']
[2025-02-22 01:28:19][+] ivanti_epmm_cve_2023_35082_vuln: name: ivanti_epmm_cve_2023_35082_vuln, author: OWASP Nettacker team, severity: 9.8, description: CVE-2023-35082 is an authentication bypass in Ivanti Endpoint Manager Mobile (EPMM) and MobileIron Core, reference: ['https://forums.ivanti.com/s/article/CVE-2023-35082-Remote-Unauthenticated-API-Access-Vulnerability-in-MobileIron-Core-11-2-and-older', 'https://www.cisa.gov/news-events/alerts/2024/01/18/cisa-adds-one-known-exploited-vulnerability-catalog', 'https://www.helpnetsecurity.com/2024/01/19/exploited-cve-2023-35082/', 'https://www.rapid7.com/blog/post/2023/08/02/cve-2023-35082-mobileiron-core-unauthenticated-api-access-vulnerability/'], profiles: ['vuln', 'vulnerability', 'http', 'high_severity', 'cve', 'ivanti', 'ivanti_epmm', 'cisa_kev']
[2025-02-22 01:28:19][+] ivanti_epmm_lastpatcheddate_scan: name: ivanti_epmm_lastpatcheddate_scan, author: OWASP Nettacker Team, severity: 3, description: Ivanti EPMM Last Patched Date Scan, reference: None, profiles: ['scan', 'http', 'ivanti', 'low_severity']
[2025-02-22 01:28:19][+] ivanti_ics_cve_2023_46805_vuln: name: ivanti_ics_cve_2023_46805_vuln, author: Jimmy Ly, severity: 8.2, description: CVE-2023-46805 is an authentication bypass that is usually chained with CVE-2024-21887 to perform remote code execution on Ivanti ICS 9.x, 22.x. This module checks whether the mitigations have been applied for CVE-2023-46805., reference: ['https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US', 'https://labs.watchtowr.com/welcome-to-2024-the-sslvpn-chaos-continues-ivanti-cve-2023-46805-cve-2024-21887'], profiles: ['vuln', 'vulnerability', 'http', 'high_severity', 'cve', 'ivanti', 'ivanti_connect_secure', 'ivanti_ics']
[2025-02-22 01:28:19][+] ivanti_ics_lastpatcheddate_scan: name: ivanti_ics_lastpatcheddate_scan, author: OWASP Nettacker Team, severity: 3, description: Ivanti ICS Last Patched Date Scan, reference: None, profiles: ['scan', 'http', 'ivanti', 'low_severity']
[2025-02-22 01:28:19][+] ivanti_vtm_version_scan: name: ivanti_vtm_version_scan, author: OWASP Nettacker Team, severity: 3, description: Ivanti vTM Version Scan, reference: https://www.helpnetsecurity.com/2024/09/25/cve-2024-7593-exploited/, profiles: ['scan', 'http', 'ivanti', 'low_severity']
[2025-02-22 01:28:19][+] joomla_template_scan: name: joomla_version_scan, author: OWASP Nettacker Team, severity: 3, description: fetch joomla version from target, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'joomla']
[2025-02-22 01:28:19][+] joomla_user_enum_scan: name: joomla_version_scan, author: OWASP Nettacker Team, severity: 3, description: fetch joomla version from target, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'joomla']
[2025-02-22 01:28:19][+] joomla_version_scan: name: joomla_version_scan, author: OWASP Nettacker Team, severity: 3, description: fetch joomla version from target, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'joomla']
[2025-02-22 01:28:19][+] justwirting_cve_2021_41878_vuln: name: justwriting_cve_2021_41878_vuln, author: OWASP Nettacker Team, severity: 6, description: A reflected cross-site scripting (XSS) vulnerability exists in the i-Panel Administration System Version 2.0 that enables a remote attacker to execute arbitrary JavaScript code in the browser-based web console., reference: ['https://cybergroot.com/cve_submission/2021-1/XSS_i-Panel_2.0.html', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41878'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve2021', 'cve', 'justwriting', 'xss']
[2025-02-22 01:28:19][+] log4j_cve_2021_44228_vuln: name: log4j_cve_2021_44228_vuln, author: OWASP Nettacker Team, severity: 9.8, description: Log4J Remote Code Execution, reference: ['https://log4shell.huntress.com/', 'https://github.com/huntresslabs/log4shell-tester'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve2021', 'cve', 'log4j', 'rce']
[2025-02-22 01:28:19][+] maxsite_cms_cve_2021_35265_vuln: name: maxsite_cms_cve_2021_35265_vuln, author: OWASP Nettacker Team, severity: 6, description: Reflected cross-site scripting (XSS) vulnerability in MaxSite CMS before V106 via product/page/* allows remote attackers to inject arbitrary web script to a page., reference: ['https://github.com/maxsite/cms/issues/414#issue-726249183', 'https://nvd.nist.gov/vuln/detail/CVE-2021-35265'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve2021', 'cve', 'maxsite', 'xss']
[2025-02-22 01:28:19][+] moveit_version_scan: name: moveit_version_scan, author: OWASP Nettacker Team, severity: 3, description: MoveIt version scan - detects and shows Progress MoveIt software and its version, reference: ['https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-15June2023'], profiles: ['scan', 'http', 'moveit', 'low_severity']
[2025-02-22 01:28:19][+] msexchange_cve_2021_26855_vuln: name: msexchange_cve_2021_26855_vuln, author: OWASP Nettacker Team, severity: 9, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'msexchange', 'cve', 'cve2021']
[2025-02-22 01:28:19][+] msexchange_cve_2021_34473_vuln: name: msexchange_cve_2021_34473_vuln, author: OWASP Nettacker Team, severity: 9, description: Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-31206., reference: ['https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473', 'https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'msexchange', 'cve', 'cve2021', 'rce']
[2025-02-22 01:28:19][+] novnc_cve_2021_3654_vuln: name: novnc_cve_2021_3654_vuln, author: OWASP Nettacker Team, severity: 3, description: A user-controlled input redirects noVNC users to an external website., reference: ['https://seclists.org/oss-sec/2021/q3/188', 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3654'], profiles: ['vuln', 'vulnerability', 'http', 'low_severity', 'cve2021', 'cve', 'novnc', 'open_redirect']
[2025-02-22 01:28:19][+] omigod_cve_2021_38647_vuln: name: omigod_cve_2021_38647_vuln, author: OWASP Nettacker Team, severity: 9, description: Open Management Infrastructure Remote Code Execution Vulnerability, reference: ['https://censys.io/blog/understanding-the-impact-of-omigod-cve-2021-38647/', 'https://github.com/microsoft/omi'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve2021', 'cve', 'omigod', 'rce']
[2025-02-22 01:28:19][+] payara_cve_2021_41381_vuln: name: payara_webtemp_cve_2021_41381_vuln, author: OWASP Nettacker Team, severity: 5, description: Payara Micro Community 5.2021.6 and below allows Directory Traversal, reference: ['https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2021-054.txt', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41381'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve2021', 'cve', 'payara', 'lfi']
[2025-02-22 01:28:19][+] phpinfo_cve_2021_37704_vuln: name: phpinfo_cve_2021_37704_vuln, author: OWASP Nettacker Team, severity: 4, description: phpinfo() exposure in unprotected composer vendor folder via phpfastcache/phpfastcache., reference: ['https://github.com/PHPSocialNetwork/phpfastcache/pull/813', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-37704'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve2021', 'cve', 'exposure', 'phpfastcache']
[2025-02-22 01:28:19][+] placeos_cve_2021_41826_vuln: name: placeos_sql_cve_2021_41826_vuln, author: OWASP Nettacker Team, severity: 3, description: PlaceOS Authentication Service before 1.29.10.0 allows app/controllers/auth/sessions_controller.rb open redirect, reference: ['https://www.exploit-db.com/exploits/50359', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41826'], profiles: ['vuln', 'vulnerability', 'http', 'low_severity', 'cve2021', 'cve', 'placeos', 'open_redirect']
[2025-02-22 01:28:19][+] pma_scan: name: pma_scan, author: OWASP Nettacker Team, severity: 3, description: php my admin finder, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity']
[2025-02-22 01:28:19][+] pop3_brute: name: pop3_brute, author: Mrinank Bhowmick, severity: 3, description: POP3 Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'pop3']
[2025-02-22 01:28:19][+] pop3s_brute: name: pop3_brute, author: OWASP Nettacker Team, severity: 3, description: POP3 SSL Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'pop3']
[2025-02-22 01:28:19][+] port_scan: id: port_scan, author: OWASP Nettacker Team, severity: 0, description: Find open ports and services, reference: None, profiles: ['scan', 'http', 'information_gathering', 'infortmation', 'info', 'low_severity']
[2025-02-22 01:28:19][+] prestashop_cve_2021_37538_vuln: name: prestashop_cve_2021_37538_vuln, author: OWASP Nettacker Team, severity: 9, description: PrestaShop SmartBlog by SmartDataSoft < 4.0.6 is vulnerable to a SQL injection in the blog archive functionality., reference: ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-37538', 'https://blog.sorcery.ie/posts/smartblog_sqli/'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve2021', 'cve', 'prestashop', 'sqli']
[2025-02-22 01:28:19][+] puneethreddyhc_sqli_cve_2021_41648_vuln: name: puneethreddyhc_sql_cve_2021_41648_vuln, author: OWASP Nettacker Team, severity: 8, description: An un-authenticated SQL Injection exists in PuneethReddyHC online-shopping-system-advanced through the /action.php prId parameter. Using a post request does not sanitize the user input., reference: ['https://github.com/MobiusBinary/CVE-2021-41648'], profiles: ['vuln', 'vulnerability', 'http', 'high_severity', 'cve2021', 'cve', 'puneethreddyhc', 'sqli']
[2025-02-22 01:28:19][+] puneethreddyhc_sqli_cve_2021_41649_vuln: name: puneethreddyhc_sql_cve_2021_41649_vuln, author: OWASP Nettacker Team, severity: 8, description: An un-authenticated SQL Injection exists in PuneethReddyHC online-shopping-system-advanced through the /homeaction.php cat_id parameter. Using a post request does not sanitize the user input., reference: ['https://github.com/MobiusBinary/CVE-2021-41649'], profiles: ['vuln', 'vulnerability', 'http', 'high_severity', 'cve2021', 'cve', 'puneethreddyhc', 'sqli']
[2025-02-22 01:28:19][+] qsan_storage_xss_cve_2021_37216_vuln: name: qsan_storage_xss_cve_2021_37216_vuln, author: OWASP Nettacker Team, severity: 6, description: QSAN Storage Manager header page parameters does not filter special characters. Remote attackers can inject JavaScript without logging in and launch reflected XSS attacks to access and modify specific data., reference: ['https://www.twcert.org.tw/tw/cp-132-4962-44cd2-1.html'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve2021', 'cve', 'qsan', 'xss']
[2025-02-22 01:28:19][+] server_version_vuln: name: server_version_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2025-02-22 01:28:19][+] smtp_brute: name: smtp_brute, author: OWASP Nettacker Team, severity: 3, description: SMTP Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'smtp']
[2025-02-22 01:28:19][+] smtps_brute: name: smtps_brute, author: OWASP Nettacker Team, severity: 3, description: SMTPS Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'smtp']
[2025-02-22 01:28:19][+] ssh_brute: name: ssh_brute, author: OWASP Nettacker Team, severity: 3, description: SSH Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'ssh']
[2025-02-22 01:28:19][+] ssl_certificate_weak_signature_vuln: name: ssl_certificate_weak_signature_vuln, author: Captain-T2004, severity: 6, description: check if there are any ssl_certificate vulnerabilities present, reference: ['https://www.ssl.com/article/ssl-tls-self-signed-certificates/'], profiles: ['scan', 'ssl']
[2025-02-22 01:28:19][+] ssl_expired_certificate_vuln: name: ssl_expired_certificate_vuln, author: Captain-T2004, severity: 6, description: check if there are any ssl_certificate vulnerabilities present, reference: ['https://www.beyondsecurity.com/resources/vulnerabilities/ssl-certificate-expiry'], profiles: ['scan', 'ssl']
[2025-02-22 01:28:19][+] ssl_expiring_certificate_scan: name: ssl_expiring_certificate_scan, author: Captain-T2004, severity: 6, description: check if the ssl certificate is expiring soon, reference: ['https://www.beyondsecurity.com/resources/vulnerabilities/ssl-certificate-expiry'], profiles: ['scan', 'ssl']
[2025-02-22 01:28:19][+] ssl_self_signed_certificate_vuln: name: ssl_self_signed_certificate_vuln, author: Captain-T2004, severity: 6, description: check if the ssl certificate is self-signed, reference: ['https://www.ssl.com/article/ssl-tls-self-signed-certificates/'], profiles: ['scan', 'ssl']
[2025-02-22 01:28:19][+] ssl_weak_cipher_vuln: name: ssl_weak_cipher_vuln, author: Captain-T2004, severity: 6, description: check if ssl version is unsafe or uses any bad ciphers., reference: ['https://www.manageengine.com/privileged-access-management/help/ssl_vulnerability.html', 'https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/'], profiles: ['scan', 'ssl']
[2025-02-22 01:28:19][+] ssl_weak_version_vuln: name: ssl_weak_version_vuln, author: Captain-T2004, severity: 6, description: check if ssl version is unsafe or uses any bad ciphers., reference: ['https://www.manageengine.com/privileged-access-management/help/ssl_vulnerability.html', 'https://www.cloudflare.com/learning/ssl/why-use-tls-1.3/'], profiles: ['scan', 'ssl']
[2025-02-22 01:28:19][+] strict_transport_security_vuln: name: strict_transport_security_vuln, author: OWASP Nettacker Team, severity: 3, description: The HTTP Strict Transport Security (Strict-Transport-Security) header informs the browser that it should never load a site using HTTP and should automatically convert all attempts to access the site using HTTP to HTTPS requests instead., reference: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security'], profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2025-02-22 01:28:19][+] subdomain_scan: name: subdomain_scan, author: OWASP Nettacker Team, severity: 0, description: Find subdomains using different sources on internet, reference: None, profiles: ['scan', 'information_gathering', 'infortmation', 'info', 'low_severity']
[2025-02-22 01:28:19][+] subdomain_takeover_vuln: name: subdomain_takeover_vuln, author: OWASP Nettacker Team, severity: 5, description: let us assume that example.com is the target and that the team running example.com have a bug bounty programme. While enumerating all of the subdomains belonging to example.com — a process that we will explore later — a hacker stumbles across subdomain.example.com, a subdomain pointing to GitHub pages. We can determine this by reviewing the subdomain's DNS records; in this example, subdomain.example.com has multiple A records pointing to GitHub's dedicated IP addresses for custom pages., reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover, profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'takeover']
[2025-02-22 01:28:19][+] teamcity_cve_2024_27198_vuln: name: teamcity_cve_2024_27198_vuln, author: OWASP Nettacker Team, severity: 9.8, description: In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible, reference: ['https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/', 'https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199-update-to-2023-11-4-now/', 'https://www.tenable.com/blog/cve-2024-27198-cve-2024-27199-two-authentication-bypass-vulnerabilities-in-jetbrains-teamcity', 'https://nvd.nist.gov/vuln/detail/CVE-2024-27198'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve', 'jetbrains', 'teamcity']
[2025-02-22 01:28:19][+] telnet_brute: name: telnet_brute, author: OWASP Nettacker Team, severity: 3, description: Telnet Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'telnet']
[2025-02-22 01:28:19][+] tieline_cve_2021_35336_vuln: name: tieline_cve_2021_35336_vuln, author: OWASP Nettacker Team, severity: 9, description: Finding the Tieline Admin Panels with default credentials., reference: ['https://pratikkhalane91.medium.com/use-of-default-credentials-to-unauthorised-remote-access-of-internal-panel-of-tieline-c1ffe3b3757c', 'https://nvd.nist.gov/vuln/detail/CVE-2021-35336'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve2021', 'cve', 'tieline']
[2025-02-22 01:28:19][+] tjws_cve_2021_37573_vuln: name: tjws_cve_2021_37573_vuln, author: OWASP Nettacker Team, severity: 6, description: A reflected cross-site scripting (XSS) vulnerability in the web server Tiny Java Web Server and Servlet Container (TJWS) <=1.115 allows an adversary to inject malicious code on the server's 404 Page not Found error page., reference: ['https://seclists.org/fulldisclosure/2021/Aug/13'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve2021', 'cve', 'tjws', 'xss']
[2025-02-22 01:28:19][+] vbulletin_cve_2019_16759_vuln: name: vbulletin_cve_2019_16759_vuln, author: OWASP Nettacker Team, severity: 9, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'vbulletin', 'cve']
[2025-02-22 01:28:19][+] viewdns_reverse_iplookup_scan: name: viewdns_reverse_iplookup_scan, author: OWASP Nettacker Team, severity: 3, description: reverse lookup for target ip, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'reverse_lookup']
[2025-02-22 01:28:19][+] waf_scan: name: waf_scan, author: OWASP Nettacker Team, severity: 3, description: waf detect, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'waf']
[2025-02-22 01:28:19][+] web_technologies_scan: name: web_technologies_scan, author: OWASP Nettacker Team, severity: 3, description: Detect Web technologies, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'web', 'whatweb', 'wappalyzer']
[2025-02-22 01:28:19][+] wordpress_version_scan: name: wordpress_version_scan, author: OWASP Nettacker Team, severity: 3, description: WordPress Version Scan - extracts WP version number from /wp-admin/install.php, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'wp', 'wordpress']
[2025-02-22 01:28:19][+] wp_plugin_cve_2021_38314_vuln: name: CVE_2021_39320_vuln, author: OWASP Nettacker Team, severity: 7, description: Sensitive Information Leakage - The Gutenberg Template Library & Redux Framework plugin <= 4.2.11 for WordPress, reference: ['https://nvd.nist.gov/vuln/detail/CVE-2021-38314', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38314'], profiles: ['vuln', 'vulnerability', 'http', 'high_severity', 'cve2021', 'cve', 'wordpress', 'redux', 'wp_plugin']
[2025-02-22 01:28:19][+] wp_plugin_cve_2021_39316_vuln: name: wp_plugin_cve_2021_39316_vuln, author: OWASP Nettacker Team, severity: 7, description: The Zoomsounds plugin <= 6.45 for WordPress allows arbitrary files, including sensitive configuration files such as wp-config.php, to be downloaded via the `dzsap_download` action using directory traversal in the `link` parameter., reference: ['https://wpscan.com/vulnerability/d2d60cf7-e4d3-42b6-8dfe-7809f87547bd', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39316'], profiles: ['vuln', 'vulnerability', 'http', 'high_severity', 'cve2021', 'cve', 'wordpress', 'lfi', 'wp_plugin']
[2025-02-22 01:28:19][+] wp_plugin_cve_2021_39320_vuln: name: wp_plugin_cve_2021_39320_vuln, author: OWASP Nettacker Team, severity: 6, description: The underConstruction plugin <= 1.18 for WordPress echoes out the raw value of `$GLOBALS['PHP_SELF']` in the ucOptions.php file. On certain configurations including Apache+modPHP, this makes it possible to use it to perform a reflected Cross-Site Scripting attack by injecting malicious code in the request path., reference: ['https://wpscan.com/vulnerability/49ae1df0-d6d2-4cbb-9a9d-bf3599429875', 'https://nvd.nist.gov/vuln/detail/CVE-2021-39320'], profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'cve2021', 'cve', 'wordpress', 'xss', 'wp_plugin']
[2025-02-22 01:28:19][+] wp_plugin_cve_2023_6875_vuln: name: wp_plugin_cve_2023_6875_vuln, author: Captain-T2004, severity: 9, description: POST SMTP Mailer – Email log, Delivery Failure Notifications and Best Mail SMTP for WordPress <= 2.8.7 – Unauthenticated Stored Cross-Site Scripting via device, reference: ['https://nvd.nist.gov/vuln/detail/CVE-2023-6875', 'https://www.wordfence.com/blog/2024/01/type-juggling-leads-to-two-vulnerabilities-in-post-smtp-mailer-wordpress-plugin/', 'https://www.cve.org/CVERecord?id=CVE-2023-6875'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve2023', 'cve', 'wordpress', 'wp_plugin']
[2025-02-22 01:28:19][+] wp_plugin_scan: name: wordpress_version_scan, author: OWASP Nettacker Team, severity: 3, description: Directory, Backup finder, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'wp', 'wordpress']
[2025-02-22 01:28:19][+] wp_theme_scan: name: wordpress_version_scan, author: OWASP Nettacker Team, severity: 3, description: Directory, Backup finder, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'wp', 'wordpress', 'wp_theme']
[2025-02-22 01:28:19][+] wp_timethumbs_scan: name: wordpress_version_scan, author: OWASP Nettacker Team, severity: 3, description: Directory, Backup finder, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'wp', 'wp_timethumbs', 'wordpress']
[2025-02-22 01:28:19][+] wp_xmlrpc_bruteforce_vuln: name: wp_xmlrpc_bruteforce_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity', 'wordpress', 'wp']
[2025-02-22 01:28:19][+] wp_xmlrpc_dos_vuln: name: wp_xmlrpc_dos_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'wordpress', 'wp']
[2025-02-22 01:28:19][+] wp_xmlrpc_pingback_vuln: name: wp_xmlrpc_pingback_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'wordpress', 'wp']
[2025-02-22 01:28:19][+] x_powered_by_vuln: name: x_powered_by_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2025-02-22 01:28:19][+] x_xss_protection_vuln: name: x_xss_protection_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2025-02-22 01:28:19][+] xdebug_rce_vuln: name: xdebug_rce_vuln, author: OWASP Nettacker Team, severity: 10, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'rce']
[2025-02-22 01:28:19][+] zoho_cve_2021_40539_vuln: name: zoho_cve_2021_40539_vuln, author: OWASP Nettacker Team, severity: 9, description: Zoho ManageEngine ADSelfService Plus version 6113 and prior is vulnerable to REST API authentication bypass with resultant remote code execution., reference: ['https://attackerkb.com/topics/DMSNq5zgcW/cve-2021-40539/rapid7-analysis', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40539'], profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve2021', 'cve', 'zoho', 'rce']
[2025-02-22 01:28:19][+] all: 

```


- you can quickly run multiple modules buundled together using profiles
```
nettacker -i example.com --profile vulnerabilities
nettacker -i example.com --profile high_severity
```

* You may want to create a new profile. To do that, you need to edit the particular modules by adding profiles name to it inside modules directory. for e.g i want add profile as `asset_discovery` to subdomain_scan,port_scan module, then you can just edit profile field in `modules/scan/subdomain.yaml` and `port_scan.yaml` 

```
info:
  name: subdomain_scan
  author: OWASP Nettacker Team
  severity: 0
  description: Find subdomains using different sources on internet
  reference:
  profiles:
    - scan
    - information_gathering
    - infortmation
    - info
    - low_severity
    - asset_discovery(new added profile)

```

* You may want to change the default values (`timeout`, `socks proxy`, `target`, `ports`) or anything that could be set with the command line.To do that, you will have to edit them in the config.py `nettacker_user_application_config()` function in the main directory in JSON style.

```python
def nettacker_user_application_config():
    """
    core framework default config (could be modify by user)

    Returns:
        a JSON with all user default configurations
    """
    from core.compatible import version_info
    return {  # OWASP Nettacker Default Configuration
        "language": "en",
        "verbose_mode": False,
        "show_version": False,
        "report_path_filename": "{results_path}/results_{date_time}_{random_chars}.html".format(
            results_path=nettacker_paths()["results_path"],
            date_time=now(model="%Y_%m_%d_%H_%M_%S"),
            random_chars=generate_random_token(10)
        ),
        "graph_name": "d3_tree_v2_graph",
        "show_help_menu": False,
        "targets": None,
        "targets_list": None,
        "selected_modules": None,
        "excluded_modules": None,
        "usernames": None,
        "usernames_list": None,
        "passwords": None,
        "passwords_list": None,
        "ports": None,
        "timeout": 3.0,
        "time_sleep_between_requests": 0.0,
        "scan_ip_range": False,
        "scan_subdomains": False,
        "thread_per_host": 250,
        "parallel_module_scan": 20,
        "socks_proxy": None,
        "retries": 1,
        "ping_before_scan": False,
        "profiles": None,
        "set_hardware_usage": "maximum",  # low, normal, high, maximum
        "user_agent": "Nettacker {version_number} {version_code} - https://github.com/OWASP/Nettacker".format(
            version_number=version_info()[0], version_code=version_info()[1]
        ),
        "show_all_modules": False,
        "show_all_profiles": False,
        "modules_extra_args": None
    }
```

# API and WebUI
API and WebUI are new interfaces through which you can send your commands to Nettacker. Technically WebUI was developed based on the present API to demonstrate an example of the current API and can be used as another easier interface. To start using this feature, simply run `nettacker --start-api`.
```
   ______          __      _____ _____
  / __ \ \        / /\    / ____|  __ \
 | |  | \ \  /\  / /  \  | (___ | |__) |
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/
 | |__| | \  /\  / ____ \ ____) | |     Version 0.4.1
  \____/   \/  \/_/    \_\_____/|_|     QUIN
                          _   _      _   _             _
                         | \ | |    | | | |           | |
  github.com/OWASP       |  \| | ___| |_| |_ __ _  ___| | _____ _ __
  owasp.org              | . ` |/ _ \ __| __/ _` |/ __| |/ / _ \ '__|
  z3r0d4y.com            | |\  |  __/ |_| || (_| | (__|   <  __/ |
                         |_| \_|\___|\__|\__\__,_|\___|_|\_\___|_|

 * API is accessible from https://nettacker-api.z3r0d4y.com:5000/ via API Key: imddfhdcncsfdrtahvvggcbznypdlwxw * Serving Flask app 'nettacker.api.engine'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on https://127.0.0.1:5000
 * Running on https://172.17.0.3:5000
Press CTRL+C to quit


```

As you can see, the API key will be a random MD5 hash every time you run the API. You don't need to set the key.
You can also add your own SSL certificate and the key to run the API on an https connection.

```nettacker --start-api --api-cert ~/cert.crt --api-cert-key ~/key.pem```

You can modify the default API config by editing the `config.py`.

```python
def nettacker_api_config():
    """
    API Config (could be modify by user)

    Returns:
        a JSON with API configuration
    """
    return {  # OWASP Nettacker API Default Configuration
        "start_api_server": False,
        "api_hostname": "0.0.0.0" if os.environ.get("docker_env") == "true" else "nettacker-api.z3r0d4y.com",
        "api_port": 5000,
        "api_debug_mode": False,
        "api_access_key": generate_random_token(32),
        "api_client_whitelisted_ips": [],  # disabled - to enable please put an array with list of ips/cidr/ranges
        # [
        #     "127.0.0.1",
        #     "10.0.0.0/24",
        #     "192.168.1.1-192.168.1.255"
        # ],
        "api_access_log": os.path.join(sys.path[0], '.data/nettacker.log'),
    }
```

## API Options
```
  --start-api           start the API service
  --api-host API_HOST   API host address
  --api-port API_PORT   API port number
  --api-debug-mode      API debug mode
  --api-access-key API_ACCESS_KEY
                        API access key
  --api-client-white-list
                        just allow white list hosts to connect to the API
  --api-client-white-list-ips API_CLIENT_WHITE_LIST_IPS
                        define white list hosts, separate with , (examples:
                        127.0.0.1, 192.168.0.1/24, 10.0.0.1-10.0.0.255)
  --api-access-log      generate API access log
  --api-access-log-filename API_ACCESS_LOG_FILENAME
                        API access log filename
  --api-cert API_CERT   API CERTIFICATE
  --api-cert-key API_CERT_KEY
                        API CERTIFICATE Key

```

## API Examples

```
nettacker --start-api --api-cert ~/cert.crt --api-cert-key ~/key.pem
nettacker --start-api --api-access-key mysecretkey
nettacker --start-api --api-client-white-list
nettacker --start-api --api-client-white-list --api-client-white-list-ips 127.0.0.1,192.168.0.1/24,10.0.0.1-10.0.0.255
nettacker --start-api --api-access-log 
nettacker --start-api --api-access-log --api-access-log-filename log.txt
nettacker --start-api --api-access-key mysecretkey --api-client-white-list --api-access-log 
nettacker --start-api --api-access-key mysecretkey --api-client-white-list --api-access-log 
nettacker --start-api --api-access-key mysecretkey --api-host 192.168.1.2 --api-port 80
nettacker --start-api --api-access-log --api-port 8080 --api-debug-mode
```

* For further information on how to use the RESTful API please visit the [API page](https://github.com/zdresearch/OWASP-Nettacker/wiki/API).

![](https://github.com/aman566/DiceGameJS/blob/master/Screencast-from-Tuesday-09-June-2020-02-32-32-IST-_online-video-cutter.com_.gif)

# Database
OWASP Nettacker currently supports three databases:
- SQLite (default)
- MySQL
- PostreSQL (requires some extra setup)
The default database is SQLite. You can, however, configure the db to your liking.
## SQLite configuration
The SQLite database can be configured in `core/config.py` file under the `_database_config()` function. Here is a sample configuration:
```
return {
        "DB": "sqlite",
        "DATABASE":  _paths()["home_path"] + "/nettacker.db", # This is the location of your db
        "USERNAME": "",
        "PASSWORD": "",
        "HOST": "",
        "PORT": ""
    }
```
## MySQL configuration:
The MySQL database can be configured in `core/config.py` file under the `_database_config()` function. Here is a sample configuration:
```
return {
        "DB": "mysql",
        "DATABASE": "nettacker", # This is the name of your db
        "USERNAME": "username",
        "PASSWORD": "password",
        "HOST": "localhost or some other host",
        "PORT": "3306 or some other custom port"
    }
```
After this configuration:
1. Open the configuration file of mysql(`/etc/mysql/my.cnf` in case of linux) as a sudo user
2. Add this to the end of the file :
``` 
[mysqld]  
sql_mode = "STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"
```
3.  Restart MySQL

## Postgres Configuration

The Postgres database can be configured in core/config.py file under the _database_config() function. Here is a sample configuration:
`
return {
        "DB": "postgreas",
        "DATABASE": "nettacker" # Name of db
        "USERNAME": "username",
        "PASSWORD": "password",
        "HOST": "localhost or some other host",
        "PORT": "5432 or some other custom port"
    }
`
After this configuration please comment out the following line in database/db.py   `connect_args={'check_same_thread': False}` 

# Nettacker User-Agent 
By default, OWASP Nettacker uses the following User-Agent string for HTTP requests:

```bash
Nettacker 0.4.1 QUIN
```
This User-Agent can be customized, allowing you to modify or randomize it according to your needs. You can configure the User-Agent using the --user-agent option when running Nettacker.
Customizing the User-Agent
If you wish to change the User-Agent, you can use the following syntax:

```bash
--user-agent USER_AGENT
```
For example, you can specify a custom User-Agent string like:

```bash
--user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
```

### Using a Random User-Agent
To use a random User-Agent string for each HTTP request, use the random_user_agent option:

```bash
--user-agent random_user_agent
```
This will pick a User-Agent from a predefined dictionary stored in the file :

```bash
nettacker/lib/payloads/User-Agents/web_browsers_user_agents.txt
```
You can modify this file to add or remove User-Agent strings as needed, ensuring that Nettacker randomly selects from a wide range of typical web browser agents.
