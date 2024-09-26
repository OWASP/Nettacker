# Help Menu

- [Target inputs Option](#target-inputs-option)
  * [Command Examples](#command-examples)
- [API and WebUI](#api-and-webui)
  * [API Options](#api-options)
  * [API Examples](#api-examples)
- [Database](#database)
  * [SQLite configuration](#sqlite-configuration)
  * [MySQL configuration](#mysql-configuration)
- [Maltego Transforms](#maltego-transforms)

By using the `--help`/`-h` switch you can read the help menu in the CLI:
 `python3 nettacker.py --help`



* Note: This example may not reflect the latest version.

```
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

You can choose from 21 languages when using Nettacker. Use the language flag: 
`$ nettacker -L fa`

The `-L` is the language flag and in this case sets the output language to Farsi, indicated by the `fa`. Farsi and 20 other languages are available, as listed in the command line help: `el`, `fr`, `en`, `nl`, `ps`, `tr`, `de`, `ko`, `it`, `ja`, `fa`, `hy`, `ar`, `zh-cn`, `vi`, `ru`, `hi`, `ur`, `id`, `es`, `iw`.

* Your CLI must support Unicode to make use of multiple languages. Search the web for "How to use Farsi on cmd/terminal."
* You can fix Persian (Farsi) and other Unicode languages RTL and Chars with [bicon](https://www.google.com/search?q=Persian+support+with+bicon&oq=Persian+support+with+bicon&aqs=chrome..69i57.178j0j7&sourceid=chrome&ie=UTF-8) in terminal/windows bash.
```
$ python nettacker.py --help -L fa
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
python nettacker.py -i 192.168.1.1,192.168.1.2-192.168.1.10,127.0.0.1,owasp.org,192.168.2.1/24 -m port_scan -g 20-100 -t 10
python nettacker.py -l targets.txt -m all -x port_scan -g 20-100 -t 5 -u root -p 123456,654321,123123
```

* Here are some more command line examples:
```
python nettacker.py -i 192.168.1.1/24 -m port_scan -t 10 -M 35 -g 20-100 --graph d3_tree_v2_graph -o result.html
python nettacker.py -i 192.168.1.1/24 -m port_scan -t 10 -M 35 -g 20-100 -o file.html --graph jit_circle_v1_graph
python nettacker.py -i 192.168.1.1/24 -m all -t 10 -M 35 -g 20-100 -o result.json -u root,user -P passwords.txt
python nettacker.py -i 192.168.1.1/24 -m all -x ssh_brute -t 10 -M 35 -g 20-100 -o file.txt -U users.txt -P passwords.txt -T 3 -w 2
```

* Using Whatcms Scan: API key can be found [here](https://whatcms.org/APIKey)
```
python nettacker.py -i eng.uber.com -m whatcms_scan --method-args whatcms_api_key=XXXX
```
* Finding CVE 2020-5902:
```
python nettacker.py -i <CIDR/IP/Domain> -m f5_cve_2020_5902
python nettacker.py -l <List of IP/CIDR/Domain> -m f5_cve_2020_5902
python nettacker.py -i <CIDR/IP/Domain> -m f5_cve_2020_5902 -s
```

* OWASP Nettacker can also scan subdomains by using this command: `-s`

```
python nettacker.py -i owasp.org -s -m port_scan -t 10 -M 35 -g 20-100 --graph d3_tree_v2_graph
```

* If you use `-r` command, it will scan the IP range automatically by getting the range from the RIPE database online.
```
python nettacker.py -i owasp.org -s -r -m port_scan -t 10 -M 35 -g 20-100 --graph d3_tree_v2_graph
python nettacker.py -i nettackerwebsiteblabla.com,owasp.org,192.168.1.1 -s -r -m all -t 10 -M 35 -g 20-100 -o file.txt -u root,user -P passwords.txt
```

* Note: If host scan finishes, and couldn't get any result nothing will be listed in the output file unless you change the verbosity mode to a value from 1 to 5.

```
python nettacker.py -i 192.168.1.1/24 -m all -t 10 -M 35 -g 20-100 -o file.txt -u root,user -P passwords.txt -v 1
```
* Use `*` pattern for selecting modules

```
python nettacker.py -i 192.168.1.1/24 -m *_scan
python nettacker.py -i 192.168.1.1/24 -m *_scan,*_vuln
```

* Use profiles for using all modules inside a given profile

```
python nettacker.py -i 192.168.1.1/24 --profile information_gathering
python nettacker.py -i 192.168.1.1/24 --profile information_gathering,vulnerabilities
python nettacker.py -i 192.168.1.1/24 --profile all
```

![](https://user-images.githubusercontent.com/24669027/39022564-bf96bde2-4453-11e8-9814-c30db364aa4d.gif)


* Use socks proxy for outgoing connections (default socks version is 5)
```
python nettacker.py -i 192.168.1.1 -m tcp_connect_port_scan -T 5 --socks-proxy socks://127.0.0.1:9050
python nettacker.py -i 192.168.1.1 -m tcp_connect_port_scan -T 5 --socks-proxy socks4://127.0.0.1:9050
python nettacker.py -i 192.168.1.1 -m tcp_connect_port_scan -T 5 --socks-proxy socks5://127.0.0.1:9050
python nettacker.py -i 192.168.1.1 -m tcp_connect_port_scan -T 5 --socks-proxy socks://username:password@127.0.0.1:9050
python nettacker.py -i 192.168.1.1 -m tcp_connect_port_scan -T 5 --socks-proxy socks4://username:password@127.0.0.1:9050
python nettacker.py -i 192.168.1.1 -m tcp_connect_port_scan -T 5 --socks-proxy socks5://username:password@127.0.0.1:9050
```

* Get the list of all modules with details about it using `--show-all-modules`
```
python nettacker.py --show-all-modules
   ______          __      _____ _____
  / __ \ \        / /\    / ____|  __ \
 | |  | \ \  /\  / /  \  | (___ | |__) |
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/
 | |__| | \  /\  / ____ \ ____) | |     Version 0.0.2
  \____/   \/  \/_/    \_\_____/|_|     BIST
                          _   _      _   _             _
                         | \ | |    | | | |           | |
  github.com/OWASP       |  \| | ___| |_| |_ __ _  ___| | _____ _ __
  owasp.org              | . ` |/ _ \ __| __/ _` |/ __| |/ / _ \ '__|
  z3r0d4y.com            | |\  |  __/ |_| || (_| | (__|   <  __/ |
                         |_| \_|\___|\__|\__\__,_|\___|_|\_\___|_|




[2021-08-31 17:42:06][+] http_options_enabled_vuln: name: http_options_enabled_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2021-08-31 17:42:06][+] clickjacking_vuln: name: clickjacking_vuln, author: OWASP Nettacker Team, severity: 5, description: Clickjacking, also known as a "UI redress attack", is when an attacker uses multiple transparent or opaque layers to trick a user into clicking on a button, reference: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html, profiles: ['vuln', 'vulnerability', 'http', 'medium_severity']
[2021-08-31 17:42:06][+] wp_xmlrpc_bruteforce_vuln: name: wp_xmlrpc_bruteforce_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity', 'wordpress', 'wp']
[2021-08-31 17:42:06][+] graphql_vuln: name: graphql_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'information_gathering', 'http', 'low_severity', 'graphql']
[2021-08-31 17:42:06][+] content_security_policy_vuln: name: content_security_policy_vuln, author: OWASP Nettacker Team, severity: 3, description: Content-Security-Policy is the name of a HTTP response header that modern browsers use to enhance the security of the document (or web page). The Content-Security-Policy header allows you to restrict how resources such as JavaScript, CSS, or pretty much anything that the browser loads., reference: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html, profiles: ['vuln', 'vulnerability', 'http', 'low_severity', 'csp']
[2021-08-31 17:42:06][+] xdebug_rce_vuln: name: xdebug_rce_vuln, author: OWASP Nettacker Team, severity: 10, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'critical_severity']
[2021-08-31 17:42:06][+] x_powered_by_vuln: name: x_powered_by_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2021-08-31 17:42:06][+] wp_xmlrpc_pingback_vuln: name: wp_xmlrpc_pingback_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'wordpress', 'wp']
[2021-08-31 17:42:06][+] http_cors_vuln: name: http_cors_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2021-08-31 17:42:06][+] f5_cve_2020_5902_vuln: name: f5_cve_2020_5902_vuln, author: OWASP Nettacker Team, severity: 9, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'cve', 'f5']
[2021-08-31 17:42:06][+] subdomain_takeover_vuln: name: subdomain_takeover_vuln, author: OWASP Nettacker Team, severity: 5, description: let us assume that example.com is the target and that the team running example.com have a bug bounty programme. While enumerating all of the subdomains belonging to example.com — a process that we will explore later — a hacker stumbles across subdomain.example.com, a subdomain pointing to GitHub pages. We can determine this by reviewing the subdomain's DNS records; in this example, subdomain.example.com has multiple A records pointing to GitHub's dedicated IP addresses for custom pages., reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover, profiles: ['vuln', 'vulnerability', 'http', 'medium_severity', 'takeover']
[2021-08-31 17:42:06][+] http_trace_enabled_vuln: name: http_trace_enabled_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2021-08-31 17:42:06][+] http_cookie_vuln: name: http_cookie_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2021-08-31 17:42:06][+] wp_xmlrpc_dos_vuln: name: wp_xmlrpc_dos_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'wordpress', 'wp']
[2021-08-31 17:42:06][+] server_version_vuln: name: server_version_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2021-08-31 17:42:06][+] x_xss_protection_vuln: name: x_xss_protection_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2021-08-31 17:42:06][+] citrix_cve_2019_19781_vuln: name: citrix_cve_2019_19781_vuln, author: OWASP Nettacker Team, severity: 8, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'high_severity', 'cve', 'citrix']
[2021-08-31 17:42:06][+] content_type_options_vuln: name: content_type_options_vuln, author: OWASP Nettacker Team, severity: 2, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity']
[2021-08-31 17:42:06][+] apache_struts_vuln: name: apache_struts_vuln, author: OWASP Nettacker Team, severity: 3, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'low_severity', 'apache_struts']
[2021-08-31 17:42:06][+] vbulletin_cve_2019_16759_vuln: name: vbulletin_cve_2019_16759_vuln, author: OWASP Nettacker Team, severity: 9, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'vbulletin', 'cve']
[2021-08-31 17:42:06][+] msexchange_cve_2021_26855_vuln: name: msexchange_cve_2021_26855_vuln, author: OWASP Nettacker Team, severity: 9, description: None, reference: None, profiles: ['vuln', 'vulnerability', 'http', 'critical_severity', 'msexchange', 'cve']
[2021-08-31 17:42:06][+] telnet_brute: name: telnet_brute, author: OWASP Nettacker Team, severity: 3, description: Telnet Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'telnet']
[2021-08-31 17:42:06][+] ssh_brute: name: ssh_brute, author: OWASP Nettacker Team, severity: 3, description: SSH Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'ssh']
[2021-08-31 17:42:06][+] smtp_brute: name: smtp_brute, author: OWASP Nettacker Team, severity: 3, description: SMTP Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'smtp']
[2021-08-31 17:42:06][+] ftps_brute: name: ftps_brute, author: OWASP Nettacker Team, severity: 3, description: FTPS Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'ftp']
[2021-08-31 17:42:06][+] smtps_brute: name: smtps_brute, author: OWASP Nettacker Team, severity: 3, description: SMTPS Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'smtp']
[2021-08-31 17:42:06][+] ftp_brute: name: ftp_brute, author: OWASP Nettacker Team, severity: 3, description: FTP Bruteforcer, reference: None, profiles: ['brute', 'brute_force', 'ftp']
[2021-08-31 17:42:06][+] whatcms_scan: name: dir_scan, author: OWASP Nettacker Team, severity: 3, description: Directory, Backup finder, reference: https://www.zaproxy.org/docs/alerts/10095/, profiles: ['scan', 'http', 'backup', 'low_severity']
[2021-08-31 17:42:06][+] icmp_scan: name: icmp_scan, author: OWASP Nettacker Team, severity: 0, description: check if host is alive through ICMP, reference: None, profiles: ['scan', 'information_gathering', 'infortmation', 'info', 'low_severity']
[2021-08-31 17:42:06][+] subdomain_scan: name: subdomain_scan, author: OWASP Nettacker Team, severity: 0, description: Find subdomains using different sources on internet, reference: None, profiles: ['scan', 'information_gathering', 'infortmation', 'info', 'low_severity']
[2021-08-31 17:42:06][+] port_scan: id: port_scan, author: OWASP Nettacker Team, severity: 0, description: Find open ports and services, reference: None, profiles: ['scan', 'http', 'information_gathering', 'infortmation', 'info', 'low_severity']
[2021-08-31 17:42:06][+] admin_scan: name: admin_scan, author: OWASP Nettacker Team, severity: 3, description: Admin Directory Finder, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity']
[2021-08-31 17:42:06][+] dir_scan: name: dir_scan, author: OWASP Nettacker Team, severity: 3, description: Directory, Backup finder, reference: https://www.zaproxy.org/docs/alerts/10095/, profiles: ['scan', 'http', 'backup', 'low_severity']
[2021-08-31 17:42:06][+] viewdns_reverse_iplookup_scan: name: viewdns_reverse_iplookup_scan, author: OWASP Nettacker Team, severity: 3, description: reverse lookup for target ip, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'reverse_lookup']
[2021-08-31 17:42:06][+] drupal_version_scan: name: drupal_version_scan, author: OWASP Nettacker Team, severity: 3, description: fetch drupal version from target, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'drupal']
[2021-08-31 17:42:06][+] joomla_version_scan: name: drupal_version_scan, author: OWASP Nettacker Team, severity: 3, description: fetch drupal version from target, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'drupal']
[2021-08-31 17:42:06][+] wordpress_version_scan: name: wordpress_version_scan, author: OWASP Nettacker Team, severity: 3, description: Directory, Backup finder, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity', 'wp', 'wordpress']
[2021-08-31 17:42:06][+] pma_scan: name: pma_scan, author: OWASP Nettacker Team, severity: 3, description: php my admin finder, reference: None, profiles: ['scan', 'http', 'backup', 'low_severity']
[2021-08-31 17:42:06][+] all:
```


- you can quick run the tool by using profiles
```
python nettacker.py -i example.com --profile vulnerabilities
python nettacker.py -i example.com --profile high_severity
```

* You may want to create a new profile. To do that, you need to edit the particular modules by adding profiles name to it inside modules directory. for e.g i want add profile as `asset_discovery` to subdomain_scan,port_scan module, then i can just edit profile field in `modules/scan/subdomain.yaml` and `port_scan.yaml` 

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
API and WebUI are new interfaces through which you can send your commands to Nettacker. Technically WebUI was developed based on the present API to demonstrate an example of the current API and can be used as another easier interface. To start using this feature, simply run `python nettacker.py --start-api`.
```
   ______          __      _____ _____  
  / __ \ \        / /\    / ____|  __ \ 
 | |  | \ \  /\  / /  \  | (___ | |__) |
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/ 
 | |__| | \  /\  / ____ \ ____) | |     Version 0.0.1  
  \____/   \/  \/_/    \_\_____/|_|     SAME
                          _   _      _   _             _            
                         | \ | |    | | | |           | |            
  github.com/zdresearch  |  \| | ___| |_| |_ __ _  ___| | _____ _ __ 
  owasp.org              | . ` |/ _ \ __| __/ _` |/ __| |/ / _ \ '__|
  zdresearch.com         | |\  |  __/ |_| || (_| | (__|   <  __/ |   
                         |_| \_|\___|\__|\__\__,_|\___|_|\_\___|_|   
                                               
    

 * API Key: ec5e067581f29a28d8c8bbfc6e548f02
 * Serving Flask app "api.engine" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on https://127.0.0.1:5000/ (Press CTRL+C to quit)

```

As you can see, the API key will be a random MD5 hash every time you run the API. You don't need to set the key.
You can also add your own SSL certificate and the key to run the API on an https connection.

```python nettacker.py --start-api --api-cert ~/cert.crt --api-cert-key ~/key.pem```

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
python nettacker.py --start-api --api-cert ~/cert.crt --api-cert-key ~/key.pem
python nettacker.py --start-api --api-access-key mysecretkey
python nettacker.py --start-api --api-client-white-list
python nettacker.py --start-api --api-client-white-list --api-client-white-list-ips 127.0.0.1,192.168.0.1/24,10.0.0.1-10.0.0.255
python nettacker.py --start-api --api-access-log 
python nettacker.py --start-api --api-access-log --api-access-log-filename log.txt
python nettacker.py --start-api --api-access-key mysecretkey --api-client-white-list --api-access-log 
python nettacker.py --start-api --api-access-key mysecretkey --api-client-white-list --api-access-log 
python nettacker.py --start-api --api-access-key mysecretkey --api-host 192.168.1.2 --api-port 80
python nettacker.py --start-api --api-access-log --api-port 8080 --api-debug-mode
```

* For further information on how to use the RESTful API please visit the [API page](https://github.com/zdresearch/OWASP-Nettacker/wiki/API).

![](https://github.com/aman566/DiceGameJS/blob/master/Screencast-from-Tuesday-09-June-2020-02-32-32-IST-_online-video-cutter.com_.gif)

# Database
OWASP Nettacker, currently supports two databases:
- SQLite
- MySQL
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



Let me know if you have any more questions.