WebUI/API Manual usage explained in the [Usage](Usage#api-and-webui) page but let's get into the structure of the request now.

- [Purpose](#purpose)
- [Requests Structure](#requests-structure)
- [New Scan](#new-scan)
- [Set Session](#set-session)
  * [Set Cookie](#set-cookie)
  * [Check Cookie](#check-cookie)
  * [UnSet Cookie](#unset-cookie)
- [Results List](#results-list)
  * [Get a Scan Result](#get-a-scan-result)
- [Hosts List](#hosts-list)
  * [Search in the Hosts](#search-in-the-hosts)
- [Generate a HTML Scan Result for a Host](#generate-a-html-scan-result-for-a-host)
  * [Get the Scan Result in JSON Type](#get-the-scan-result-in-json-type)


## Purpose 

API usage purposes depend on the users, Some of them may want to scan their local company to monitor the network, This feature let all security staff use OWASP Nettacker on a shared server safely. API supports SSL. User can give their own Certificate and the key to run server on HTTPS.


## Requests Structure

```
am4n@am4n-HP-ProBook-450-G4:~/Documents/OWASP-Nettacker$ python nettacker.py --start-api
    
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
                                               
    

 * API Key: 2608863752f1f89fa385e43c76c2853b
 * Serving Flask app "api.engine" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on https://127.0.0.1:5000/ (Press CTRL+C to quit)

```

At the first, you must send an API key through the request each time you send a request in `GET`, `POST`, or `Cookies` in the value named `key` or you will get `401` error in the restricted area.

```python
>>> import requests
>>> from requests.packages.urllib3.exceptions import InsecureRequestWarning
>>> requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
>>> r = requests.get('https://127.0.0.1:5000/?key=8370bd0a0b9a98ac25b341833fb0fb07')
>>> r.status_code
200
>>> r = requests.post('https://127.0.0.1:5000/', data={"key": "8370bd0a0b9a98ac25b341833fb0fb07"})
>>> r.status_code
200
>>> r = requests.get('https://127.0.0.1:5000/', cookies={"key": "8370bd0a0b9a98ac25b341833fb0fb07"})
>>> r.status_code
200
>>> r = requests.get('https://127.0.0.1:5000/new/scan', cookies={"key": "wrong_key"})
>>> r.status_code
401
```

## New Scan

To submit a new scan follow this step.

```python
>>> r = requests.post('https://127.0.0.1:5000/new/scan', data={"key": "8370bd0a0b9a98ac25b341833fb0fb07", "targets": "127.0.0.1,owasp.org", "scan_method": "port_scan"})
>>> r.status_code
200
>>> import json
>>> print json.dumps(json.loads(r.content), sort_keys=True, indent=4)
{
    "backup_ports": null, 
    "check_ranges": false, 
    "check_subdomains": false, 
    "database_host": "", 
    "database_name": "/home/am4n/owasp-nettacker/.data/nettacker.db", 
    "database_password": "", 
    "database_port": "", 
    "database_type": "sqlite", 
    "database_username": "", 
    "graph_flag": "d3_tree_v2_graph", 
    "home_path": "/home/am4n/owasp-nettacker/.data", 
    "language": "en", 
    "log_in_file": "/home/am4n/owasp-nettacker/.data/results/results_2020_06_09_10_36_56_mibtrtoacd.html", 
    "methods_args": {
        "as_user_set": "set_successfully"
    }, 
    "passwds": null, 
    "ping_flag": false, 
    "ports": null, 
    "profile": null, 
    "results_path": "/home/am4n/owasp-nettacker/.data/results", 
    "retries": 3, 
    "scan_method": [
        "port_scan"
    ], 
    "socks_proxy": null, 
    "targets": [
        "owasp.org"
    ], 
    "thread_number": 100, 
    "thread_number_host": 5, 
    "time_sleep": 0.0, 
    "timeout_sec": 3, 
    "tmp_path": "/home/am4n/owasp-nettacker/.data/tmp", 
    "users": null, 
    "verbose_level": 0
}
```

Please note, `targets` and `scan_method` are **necessary** to submit a new scan unless you modify the config file before! The `scan_method` could be empty if you define the `profile`.

```python
>>> r = requests.post('https://127.0.0.1:5000/new/scan', data={"key": "8370bd0a0b9a98ac25b341833fb0fb07"})
>>> r.content
'{"msg":"Cannot specify the target(s)","status":"error"}\n'

>>> r = requests.post('https://127.0.0.1:5000/new/scan', data={"key": "09877e92c75f6afdca6ae61ad3f53727", "targets": "127.0.0.1"})
>>> r.content
u'{"msg":"please choose your scan method!","status":"error"}\n'

>>> r = requests.post('https://127.0.0.1:5000/new/scan', data={"key": "09877e92c75f6afdca6ae61ad3f53727", "targets": "127.0.0.1", "scan_method": "dir_scan,port_scan"})
>>> print json.dumps(json.loads(r.content), sort_keys=True, indent=4)
{
    "backup_ports": null, 
    "check_ranges": false, 
    "check_subdomains": false, 
    "database_host": "", 
    "database_name": "/home/am4n/owasp-nettacker/.data/nettacker.db", 
    "database_password": "", 
    "database_port": "", 
    "database_type": "sqlite", 
    "database_username": "", 
    "graph_flag": "d3_tree_v2_graph", 
    "home_path": "/home/am4n/owasp-nettacker/.data", 
    "language": "en", 
    "log_in_file": "/home/am4n/owasp-nettacker/.data/results/results_2020_06_09_10_47_08_dugacttfmf.html", 
    "methods_args": {
        "as_user_set": "set_successfully"
    }, 
    "passwds": null, 
    "ping_flag": false, 
    "ports": null, 
    "profile": null, 
    "results_path": "/home/am4n/owasp-nettacker/.data/results", 
    "retries": 3, 
    "scan_method": [
        "dir_scan", 
        "port_scan"
    ], 
    "socks_proxy": null, 
    "targets": [
        "127.0.0.1"
    ], 
    "thread_number": 100, 
    "thread_number_host": 5, 
    "time_sleep": 0.0, 
    "timeout_sec": 3, 
    "tmp_path": "/home/am4n/owasp-nettacker/.data/tmp", 
    "users": null, 
    "verbose_level": 0
}
>>> r = requests.post('https://127.0.0.1:5000/new/scan', data={"key": "09877e92c75f6afdca6ae61ad3f53727", "targets": "127.0.0.1", "profile": "information_gathering"})
>>> print json.dumps(json.loads(r.content), sort_keys=True, indent=4)
{
    "backup_ports": null, 
    "check_ranges": false, 
    "check_subdomains": false, 
    "database_host": "", 
    "database_name": "/home/am4n/owasp-nettacker/.data/nettacker.db", 
    "database_password": "", 
    "database_port": "", 
    "database_type": "sqlite", 
    "database_username": "", 
    "graph_flag": "d3_tree_v2_graph", 
    "home_path": "/home/am4n/owasp-nettacker/.data", 
    "language": "en", 
    "log_in_file": "/home/am4n/owasp-nettacker/.data/results/results_2020_06_09_10_50_09_xjqatmkngn.html", 
    "methods_args": {
        "as_user_set": "set_successfully"
    }, 
    "passwds": null, 
    "ping_flag": false, 
    "ports": null, 
    "profile": "information_gathering", 
    "results_path": "/home/am4n/owasp-nettacker/.data/results", 
    "retries": 3, 
    "scan_method": [
        "port_scan"
    ], 
    "socks_proxy": null, 
    "targets": [
        "127.0.0.1"
    ], 
    "thread_number": 100, 
    "thread_number_host": 5, 
    "time_sleep": 0.0, 
    "timeout_sec": 3, 
    "tmp_path": "/home/am4n/owasp-nettacker/.data/tmp", 
    "users": null, 
    "verbose_level": 0
}

>>>

```

All variables in JSON you've got in results could be changed in `GET`/`POST`/`Cookies`, you can fill them all just like normal CLI commands. (e.g. same scan method name (modules), you can separate with `,`, you can use `ports` like `80,100-200,1000,2000`, set users and passwords `user1,user2`, `passwd1,passwd2`). You cannot use `read_from_file:/tmp/users.txt` syntax in `methods_args`. if you want to send a big password list, just send it through the `POST` requests and separated with `,`.

## Set Session

To enable session-based requests, like (e.g. Python `requests.session()` or browsers), I developed a feature to interact with Cookie.

### Set Cookie

```python
>>> s = requests.session()
>>> r = s.get("https://localhost:5000/session/set?key=09877e92c75f6afdca6ae61ad3f53727")
>>> print json.dumps(json.loads(r.content), sort_keys=True, indent=4)
{
    "msg": "your browser session is valid", 
    "status": "ok"
}
>>> print r.cookies
<RequestsCookieJar[<Cookie key=09877e92c75f6afdca6ae61ad3f53727 for localhost.local/>]>
>>> r = s.get("https://localhost:5000/new/scan")
>>> print r.content
{
  "msg": "Cannot specify the target(s)",
  "status": "error"
}

>>>
```
### Check Cookie

```python
>>> r = s.get("https://localhost:5000/session/check")
>>> print r.content
{
  "msg": "your browser session is valid",
  "status": "ok"
}
```
### UnSet Cookie

```python
>>> r = s.get("https://localhost:5000/session/kill")
>>> print r.content
{
  "msg": "your browser session killed",
  "status": "ok"
}

>>> print r.cookies
<RequestsCookieJar[]>
>>>
```

## Results List

```python
>>> r = s.get("https://localhost:5000/results/get_list?page=1")
>>> print(json.dumps(json.loads(r.content), sort_keys=True, indent=4))
[
    {
        "api_flag": 0, 
        "category": "vuln,brute,scan", 
        "date": "2020-06-09 11:08:45", 
        "events_num": 317, 
        "graph_flag": "d3_tree_v2_graph", 
        "id": 8, 
        "language": "en", 
        "ports": "default", 
        "profile": null, 
        "report_filename": "/home/am4n/owasp-nettacker/.data/results/results_2020_06_09_11_04_17_pisajfbfyp.html", 
        "report_type": "HTML", 
        "scan_cmd": "nettacker.py -i 127.0.0.1 -m all -M 100", 
        "scan_id": "b745337b4feeb99cee3eb4ff4cb45fad", 
        "scan_method": "XSS_protection_vuln,ProFTPd_directory_traversal_vuln,port_scan,telnet_brute,ssl_certificate_expired_vuln,http_form_brute,ProFTPd_integer_overflow_vuln,heartbleed_vuln,joomla_user_enum_scan,http_basic_auth_brute,http_ntlm_brute,wp_user_enum_scan,ProFTPd_restriction_bypass_vuln,http_cors_vuln,apache_struts_vuln,wordpress_version_scan,clickjacking_vuln,wp_xmlrpc_bruteforce_vuln,cms_detection_scan,wordpress_dos_cve_2018_6389_vuln,content_security_policy_vuln,pma_scan,ftp_brute,wp_theme_scan,wappalyzer_scan,wp_xmlrpc_brute,wp_xmlrpc_pingback_vuln,smtp_brute,drupal_version_scan,ProFTPd_memory_leak_vuln,wp_plugin_scan,ssh_brute,joomla_template_scan,wp_timthumbs_scan,self_signed_certificate_vuln,Bftpd_memory_leak_vuln,CCS_injection_vuln,dir_scan,viewdns_reverse_ip_lookup_scan,Bftpd_parsecmd_overflow_vuln,icmp_scan,ProFTPd_exec_arbitary_vuln,server_version_vuln,x_powered_by_vuln,admin_scan,citrix_cve_2019_19781_vuln,joomla_version_scan,sender_policy_scan,ProFTPd_cpu_consumption_vuln,Bftpd_double_free_vuln,drupal_theme_scan,ProFTPd_heap_overflow_vuln,weak_signature_algorithm_vuln,drupal_modules_scan,subdomain_scan,Bftpd_remote_dos_vuln,content_type_options_vuln,xdebug_rce_vuln,options_method_enabled_vuln,ProFTPd_bypass_sqli_protection_vuln", 
        "verbose": 0
    }, 
    {
        "api_flag": 0, 
        "category": "vuln,brute,scan", 
        "date": "2020-06-09 11:08:42", 
        "events_num": 372, 
        "graph_flag": "d3_tree_v2_graph", 
        "id": 7, 
        "language": "en", 
        "ports": "default", 
        "profile": null, 
        "report_filename": "/home/am4n/owasp-nettacker/.data/results/results_2020_06_09_11_04_04_bdzipsmtcc.html", 
        "report_type": "HTML", 
        "scan_cmd": "nettacker.py -i 127.0.0.1 -m all", 
        "scan_id": "8e9a1b2fd03cb7b969d99beea1cff2aa", 
        "scan_method": "XSS_protection_vuln,ProFTPd_directory_traversal_vuln,port_scan,telnet_brute,ssl_certificate_expired_vuln,http_form_brute,ProFTPd_integer_overflow_vuln,heartbleed_vuln,joomla_user_enum_scan,http_basic_auth_brute,http_ntlm_brute,wp_user_enum_scan,ProFTPd_restriction_bypass_vuln,http_cors_vuln,apache_struts_vuln,wordpress_version_scan,clickjacking_vuln,wp_xmlrpc_bruteforce_vuln,cms_detection_scan,wordpress_dos_cve_2018_6389_vuln,content_security_policy_vuln,pma_scan,ftp_brute,wp_theme_scan,wappalyzer_scan,wp_xmlrpc_brute,wp_xmlrpc_pingback_vuln,smtp_brute,drupal_version_scan,ProFTPd_memory_leak_vuln,wp_plugin_scan,ssh_brute,joomla_template_scan,wp_timthumbs_scan,self_signed_certificate_vuln,Bftpd_memory_leak_vuln,CCS_injection_vuln,dir_scan,viewdns_reverse_ip_lookup_scan,Bftpd_parsecmd_overflow_vuln,icmp_scan,ProFTPd_exec_arbitary_vuln,server_version_vuln,x_powered_by_vuln,admin_scan,citrix_cve_2019_19781_vuln,joomla_version_scan,sender_policy_scan,ProFTPd_cpu_consumption_vuln,Bftpd_double_free_vuln,drupal_theme_scan,ProFTPd_heap_overflow_vuln,weak_signature_algorithm_vuln,drupal_modules_scan,subdomain_scan,Bftpd_remote_dos_vuln,content_type_options_vuln,xdebug_rce_vuln,options_method_enabled_vuln,ProFTPd_bypass_sqli_protection_vuln", 
        "verbose": 0
    }, 
    {
        "api_flag": 0, 
        "category": "vuln,brute,scan", 
        "date": "2020-06-09 11:06:52", 
        "events_num": 1016, 
        "graph_flag": "d3_tree_v2_graph", 
        "id": 6, 
        "language": "en", 
        "ports": "default", 
        "profile": null, 
        "report_filename": "/home/am4n/owasp-nettacker/.data/results/results_2020_06_09_11_03_23_ubytvgauvj.html", 
        "report_type": "HTML", 
        "scan_cmd": "nettacker.py -i 127.0.0.1 -m all -M 100 -t 1000", 
        "scan_id": "7d84af54f343e19671d1c52357bf928f", 
        "scan_method": "XSS_protection_vuln,ProFTPd_directory_traversal_vuln,port_scan,telnet_brute,ssl_certificate_expired_vuln,http_form_brute,ProFTPd_integer_overflow_vuln,heartbleed_vuln,joomla_user_enum_scan,http_basic_auth_brute,http_ntlm_brute,wp_user_enum_scan,ProFTPd_restriction_bypass_vuln,http_cors_vuln,apache_struts_vuln,wordpress_version_scan,clickjacking_vuln,wp_xmlrpc_bruteforce_vuln,cms_detection_scan,wordpress_dos_cve_2018_6389_vuln,content_security_policy_vuln,pma_scan,ftp_brute,wp_theme_scan,wappalyzer_scan,wp_xmlrpc_brute,wp_xmlrpc_pingback_vuln,smtp_brute,drupal_version_scan,ProFTPd_memory_leak_vuln,wp_plugin_scan,ssh_brute,joomla_template_scan,wp_timthumbs_scan,self_signed_certificate_vuln,Bftpd_memory_leak_vuln,CCS_injection_vuln,dir_scan,viewdns_reverse_ip_lookup_scan,Bftpd_parsecmd_overflow_vuln,icmp_scan,ProFTPd_exec_arbitary_vuln,server_version_vuln,x_powered_by_vuln,admin_scan,citrix_cve_2019_19781_vuln,joomla_version_scan,sender_policy_scan,ProFTPd_cpu_consumption_vuln,Bftpd_double_free_vuln,drupal_theme_scan,ProFTPd_heap_overflow_vuln,weak_signature_algorithm_vuln,drupal_modules_scan,subdomain_scan,Bftpd_remote_dos_vuln,content_type_options_vuln,xdebug_rce_vuln,options_method_enabled_vuln,ProFTPd_bypass_sqli_protection_vuln", 
        "verbose": 0
    }, 
    {
        "api_flag": 0, 
        "category": "vuln,brute,scan", 
        "date": "2020-06-09 11:01:14", 
        "events_num": 1017, 
        "graph_flag": "d3_tree_v2_graph", 
        "id": 5, 
        "language": "en", 
        "ports": "default", 
        "profile": null, 
        "report_filename": "/home/am4n/owasp-nettacker/.data/results/results_2020_06_09_10_59_29_oyzxmegtuk.html", 
        "report_type": "HTML", 
        "scan_cmd": "nettacker.py -i 127.0.0.1 -m all -t 1000", 
        "scan_id": "d944c9a02053fd387d1e3343fec6b320", 
        "scan_method": "XSS_protection_vuln,ProFTPd_directory_traversal_vuln,port_scan,telnet_brute,ssl_certificate_expired_vuln,http_form_brute,ProFTPd_integer_overflow_vuln,heartbleed_vuln,joomla_user_enum_scan,http_basic_auth_brute,http_ntlm_brute,wp_user_enum_scan,ProFTPd_restriction_bypass_vuln,http_cors_vuln,apache_struts_vuln,wordpress_version_scan,clickjacking_vuln,wp_xmlrpc_bruteforce_vuln,cms_detection_scan,wordpress_dos_cve_2018_6389_vuln,content_security_policy_vuln,pma_scan,ftp_brute,wp_theme_scan,wappalyzer_scan,wp_xmlrpc_brute,wp_xmlrpc_pingback_vuln,smtp_brute,drupal_version_scan,ProFTPd_memory_leak_vuln,wp_plugin_scan,ssh_brute,joomla_template_scan,wp_timthumbs_scan,self_signed_certificate_vuln,Bftpd_memory_leak_vuln,CCS_injection_vuln,dir_scan,viewdns_reverse_ip_lookup_scan,Bftpd_parsecmd_overflow_vuln,icmp_scan,ProFTPd_exec_arbitary_vuln,server_version_vuln,x_powered_by_vuln,admin_scan,citrix_cve_2019_19781_vuln,joomla_version_scan,sender_policy_scan,ProFTPd_cpu_consumption_vuln,Bftpd_double_free_vuln,drupal_theme_scan,ProFTPd_heap_overflow_vuln,weak_signature_algorithm_vuln,drupal_modules_scan,subdomain_scan,Bftpd_remote_dos_vuln,content_type_options_vuln,xdebug_rce_vuln,options_method_enabled_vuln,ProFTPd_bypass_sqli_protection_vuln", 
        "verbose": 0
    }, 
    {
        "api_flag": 0, 
        "category": "scan", 
        "date": "2020-06-09 10:50:18", 
        "events_num": 9, 
        "graph_flag": "d3_tree_v2_graph", 
        "id": 4, 
        "language": "en", 
        "ports": "default", 
        "profile": "information_gathering", 
        "report_filename": "/home/am4n/owasp-nettacker/.data/results/results_2020_06_09_10_50_09_xjqatmkngn.html", 
        "report_type": "HTML", 
        "scan_cmd": "Through the OWASP Nettacker API", 
        "scan_id": "05ba4e5b839b5ba525c9a35baa8864a1", 
        "scan_method": "port_scan", 
        "verbose": 0
    }, 
    {
        "api_flag": 0, 
        "category": "scan", 
        "date": "2020-06-09 10:47:17", 
        "events_num": 9, 
        "graph_flag": "d3_tree_v2_graph", 
        "id": 3, 
        "language": "en", 
        "ports": "default", 
        "profile": null, 
        "report_filename": "/home/am4n/owasp-nettacker/.data/results/results_2020_06_09_10_47_08_dugacttfmf.html", 
        "report_type": "HTML", 
        "scan_cmd": "Through the OWASP Nettacker API", 
        "scan_id": "18af7af856b4ceefac659a59c4908088", 
        "scan_method": "dir_scan,port_scan", 
        "verbose": 0
    }, 
    {
        "api_flag": 0, 
        "category": "scan", 
        "date": "2020-06-09 10:38:50", 
        "events_num": 0, 
        "graph_flag": "d3_tree_v2_graph", 
        "id": 2, 
        "language": "en", 
        "ports": "default", 
        "profile": null, 
        "report_filename": "/home/am4n/owasp-nettacker/.data/results/results_2020_06_09_10_35_10_jvxotwxako.html", 
        "report_type": "HTML", 
        "scan_cmd": "Through the OWASP Nettacker API", 
        "scan_id": "78d253c3a28d2bb4f467ac040ccaa854", 
        "scan_method": "port_scan", 
        "verbose": 0
    }, 
    {
        "api_flag": 0, 
        "category": "scan", 
        "date": "2020-06-09 10:38:49", 
        "events_num": 3, 
        "graph_flag": "d3_tree_v2_graph", 
        "id": 1, 
        "language": "en", 
        "ports": "default", 
        "profile": null, 
        "report_filename": "/home/am4n/owasp-nettacker/.data/results/results_2020_06_09_10_36_56_mibtrtoacd.html", 
        "report_type": "HTML", 
        "scan_cmd": "Through the OWASP Nettacker API", 
        "scan_id": "708e1dcf0f2ce9fe71038ccea7bf28bb", 
        "scan_method": "port_scan", 
        "verbose": 0
    }
]
```

### Get a Scan Result

```python
>>> r = s.get("https://localhost:5000/results/get?id=8")
>>> print r.content[:500]
<!DOCTYPE html>
<!-- THIS PAGE COPIED AND MODIFIED FROM http://bl.ocks.org/robschmuecker/7880033-->
<title>OWASP Nettacker Report</title>
<meta charset="utf-8">
<div class="header">
    <h3><a href="https://github.com/zdresearch/nettacker">OWASP Nettacker</a></h3>
    <h3>Penetration Testing Graphs</h3>
</div>
<style type="text/css">

	.header{
    margin:2%;
    text-align:center;
  }
  .node {
    cursor: pointer;
  }

  .overlay{
      background-color:#EEE;
  }

  .node circle {
    fill: #f

...

```

## Hosts List
```python
>>> r = s.get("https://localhost:5000/logs/search?q=&page=1")
>>> print json.dumps(json.loads(r.content), sort_keys=True, indent=4)
[
    {
        "host": "owasp.org", 
        "info": {
            "category": [
                "scan"
            ], 
            "descriptions": [
                "8443/http/TCP_CONNECT", 
                "80/http/TCP_CONNECT", 
                "443/http/TCP_CONNECT"
            ], 
            "open_ports": [], 
            "scan_methods": [
                "port_scan"
            ]
        }
    }
]


>>>
```

### Search in the Hosts

```python
>>> r = s.get("https://localhost:5000/logs/search?q=port_scan&page=3")
>>> print r.content
[
  {
    "host": "owasp4.owasp.org",
    "info": {
      "category": [
        "scan"
      ],
      "descriptions": [
        "22/TCP_CONNECT",
        "80/TCP_CONNECT"
      ],
      "open_ports": [
        22,
        80
      ],
      "scan_methods": [
        "port_scan"
      ]
    }
  },
  {
    "host": "new-wiki.owasp.org",
    "info": {
      "category": [
        "scan"
      ],
      "descriptions": [
        "22/TCP_CONNECT",
        "80/TCP_CONNECT"
      ],
      "open_ports": [
        22,
        80
      ],
      "scan_methods": [
        "port_scan"
      ]
    }
  },
  {
    "host": "cheesemonkey.owasp.org",
    "info": {
      "category": [
        "scan"
      ],
      "descriptions": [
        "80/TCP_CONNECT"
      ],
      "open_ports": [
        80
      ],
      "scan_methods": [
        "port_scan"
      ]
    }
  },
  {
    "host": "5.79.66.240",
    "info": {
      "category": [
        "scan"
      ],
      "descriptions": [
        "filesmog.com",
        "\u062f\u0631\u06af\u0627\u0647 \u0628\u0627\u0632"
      ],
      "open_ports": [
        5901,
        6001,
        22
      ],
      "scan_methods": [
        "viewdns_reverse_ip_lookup_scan",
        "port_scan"
      ]
    }
  },
  {
    "host": "5.79.66.237",
    "info": {
      "category": [
        "scan"
      ],
      "descriptions": [
        "\u062f\u0631\u06af\u0627\u0647 \u0628\u0627\u0632",
        "http://5.79.66.237/robots.txt \u067e\u06cc\u062f\u0627 \u0634\u062f!(OK:200)",
        "http://5.79.66.237/.htaccess.txt \u067e\u06cc\u062f\u0627 \u0634\u062f!(Forbidden:403)",
        "http://5.79.66.237/.htaccess.save \u067e\u06cc\u062f\u0627 \u0634\u062f!(Forbidden:403)",
        "http://5.79.66.237/phpmyadmin \u067e\u06cc\u062f\u0627 \u0634\u062f!(OK:200)",
        "http://5.79.66.237/.htaccess.old \u067e\u06cc\u062f\u0627 \u0634\u062f!(Forbidden:403)",
        "http://5.79.66.237/.htaccess \u067e\u06cc\u062f\u0627 \u0634\u062f!(Forbidden:403)",
        "http://5.79.66.237/server-status \u067e\u06cc\u062f\u0627 \u0634\u062f!(Forbidden:403)",
        "http://5.79.66.237//phpmyadmin/ \u067e\u06cc\u062f\u0627 \u0634\u062f!(OK:200)",
        "http://5.79.66.237//phpMyAdmin/ \u067e\u06cc\u062f\u0627 \u0634\u062f!(OK:200)",
        "offsec.ir"
      ],
      "open_ports": [
        8083,
        8000,
        443,
        80,
        22,
        21
      ],
      "scan_methods": [
        "port_scan",
        "dir_scan",
        "pma_scan",
        "viewdns_reverse_ip_lookup_scan"
      ]
    }
  },
  {
    "host": "192.168.1.124",
    "info": {
      "category": [
        "scan"
      ],
      "descriptions": [
        "2179/TCP_CONNECT",
        "445/TCP_CONNECT",
        "135/TCP_CONNECT",
        "22/TCP_CONNECT",
        "139/TCP_CONNECT",
        "zhanpang.cn",
        "yowyeh.cn",
        "treelights.website",
        "sxyhed.com",
        "redlxin.com",
        "ppoo6.com",
        "miancan.cn",
        "maynard.top",
        "liyedai.site",
        "linterfund.com",
        "li5xs.com",
        "hxinglan.win",
        "heresylly.top",
        "gzptjwangye.bid",
        "eatpeanutfree.com",
        "comgmultiservices.com",
        "biyao123.com"
      ],
      "open_ports": [
        2179,
        445,
        135,
        22,
        139
      ],
      "scan_methods": [
        "port_scan",
        "viewdns_reverse_ip_lookup_scan"
      ]
    }
  },
  {
    "host": "192.168.1.127",
    "info": {
      "category": [
        "scan"
      ],
      "descriptions": [
        "49152/TCP_CONNECT",
        "49154/TCP_CONNECT",
        "49155/TCP_CONNECT",
        "49153/TCP_CONNECT"
      ],
      "open_ports": [
        49152,
        49154,
        49155,
        49153
      ],
      "scan_methods": [
        "port_scan"
      ]
    }
  }
]

>>>
```
## Generate a HTML Scan Result for a Host
```python
>>> r = s.get("https://localhost:5000/logs/get_html?host=127.0.0.1")
>>> print r.content[:1000]
<!DOCTYPE html>
<!-- THIS PAGE COPIED AND MODIFIED FROM http://bl.ocks.org/robschmuecker/7880033-->
<title>OWASP Nettacker Report</title>
<meta charset="utf-8">
<div class="header">
    <h3><a href="https://github.com/zdresearch/nettacker">OWASP Nettacker</a></h3>
    <h3>Penetration Testing Graphs</h3>
</div>
<style type="text/css">

	.header{
    margin:2%;
    text-align:center;
  }
  .node {
    cursor: pointer;
  }

  .overlay{
      background-color:#EEE;
  }

  .node circle {
    fill: #fff;
    stroke: steelblue;
    stroke-width: 1.5px;
  }

  .node text {
    font-size:12px;
    font-family:sans-serif;
  }
...
...
>>>
```

### Get the Scan Result in JSON Type
```python
>>> r = s.get("https://localhost:5000/logs/get_json?host=owasp.org")
>>> print(json.dumps(json.loads(r.content), sort_keys=True, indent=4))
[
    {
        "DESCRIPTION": "443/http/TCP_CONNECT", 
        "HOST": "owasp.org", 
        "PASSWORD": "", 
        "PORT": "443", 
        "SCAN_ID": "708e1dcf0f2ce9fe71038ccea7bf28bb", 
        "TIME": "2020-06-09 10:36:59", 
        "TYPE": "port_scan", 
        "USERNAME": ""
    }, 
    {
        "DESCRIPTION": "80/http/TCP_CONNECT", 
        "HOST": "owasp.org", 
        "PASSWORD": "", 
        "PORT": "80", 
        "SCAN_ID": "708e1dcf0f2ce9fe71038ccea7bf28bb", 
        "TIME": "2020-06-09 10:36:59", 
        "TYPE": "port_scan", 
        "USERNAME": ""
    }, 
    {
        "DESCRIPTION": "8443/http/TCP_CONNECT", 
        "HOST": "owasp.org", 
        "PASSWORD": "", 
        "PORT": "8443", 
        "SCAN_ID": "708e1dcf0f2ce9fe71038ccea7bf28bb", 
        "TIME": "2020-06-09 10:38:17", 
        "TYPE": "port_scan", 
        "USERNAME": ""
    }
]
>>>
```