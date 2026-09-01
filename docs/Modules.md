# Nettacker modules

Nettacker modules define the checks that run against a target. Each module belongs to one of
three categories:

- **Scan** modules discover hosts, services, technologies, and other information ("scan" for something).
- **Vuln** (**Vulnerability**) modules check for a specific vulnerability (e.g. a CVE) or insecure configuration.
- **Brute** (**Brute-force**) modules test authentication using supplied or module-defined credentials.

> Only scan systems you own or have explicit permission to test!


## On this page

- [Find and select modules](#find-and-select-modules)
- [Ports and service discovery](#ports-and-service-discovery)
- [Module-specific values](#module-specific-values)
- [Available modules](#available-modules)
  - [Scan modules](#scan-modules)
  - [Vulnerability modules](#vulnerability-modules)
  - [Brute-force modules](#brute-force-modules)

## Find and select modules

Module identifiers end in `_scan`, `_vuln`, or `_brute`. Identifiers are case-sensitive and must
be passed exactly as shown by the CLI:

```console
python nettacker.py --show-all-modules
python nettacker.py --show-all-profiles
```

`--show-all-modules` is the authoritative source for the installed version. It includes each
module's description, author, severity, references, and profiles.

Run one module, or separate multiple modules with commas:

```console
python nettacker.py -i scanme.example -m http_status_scan
python nettacker.py -i scanme.example \
  -m http_status_scan,ssl_expiring_certificate_scan
```

Profiles select every module tagged with a particular capability or technology. Profiles and
explicit module selections can be combined, and `-x` excludes modules from the result:

```console
python nettacker.py -i scanme.example --profile http
python nettacker.py -i scanme.example --profile http -x dir_scan,admin_scan
```

See the [usage guide](Usage.md) for all target, output, concurrency, and reporting options.

## Ports and service discovery

Nettacker normally performs service discovery (port scan of 1,005 most-popular ports) before running modules and limits protocol-specific
checks to compatible discovered services. Use `-d` or `--skip-service-discovery` only when you
intentionally want to run selected modules without that filtering.

The `port_scan` module's default ports are maintained in
[`nettacker/modules/scan/port.yaml`](../nettacker/modules/scan/port.yaml). 

Use `-g` or `--ports` to replace the default selection. Use `-X` or `--exclude-ports` to remove ports
from the effective selection. Both options accept a single port, comma-separated ports, inclusive
ranges, or a mixture of those forms. Exclusions are applied after the default or `--ports`
selection:


```console
python nettacker.py -i scanme.example -m port_scan -g 22,80,443,8000-8100
python nettacker.py -i scanme.example -m port_scan -X 25,110,445
```

`-g 1-65535` requests all TCP ports. A full-port scan is substantially slower and noisier than the
default selection.

<details open>
<summary>Show the 1,005 default ports used by <code>port_scan</code></summary>

```text
1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26
30, 32, 33, 37, 42, 43, 49, 53, 67, 68, 69, 70, 79, 80, 81, 82
83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135
139, 143, 144, 146, 161, 162, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259
264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444
445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545
548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668
683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800
801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990
992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025
1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041
1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057
1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073
1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089
1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107
1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132
1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174
1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236
1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328
1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556
1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723
1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935
1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008
2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045
2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126
2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323
2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604
2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909
2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031
3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322
3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517
3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826
3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995
3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279
4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001
5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102
5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432
5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800
5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904
5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988
5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101
6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646
6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000
7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496
7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001
8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084
8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222
8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654
8701, 8800, 8843, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050
9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290
9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878
9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010
10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110
11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002
15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040
18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571
22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718
30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780
32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510
44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161
49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636
50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294
57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389
```

</details>

## Module-specific values

`--modules-extra-args` supplies template values as an ampersand-separated `name=value` string.
Quote the argument so the shell does not interpret `&`:

```console
python nettacker.py -i scanme.example -m dir_scan \
  --modules-extra-args "url_base_path=application/&user_agent=AuthorizedAssessment"
```

Values are shared by the selected modules, so use names expected by their YAML templates. Boolean,
numeric, JSON-array, and JSON-object values are converted when possible; other values remain text.


## Available modules

The following catalog mirrors the YAML templates in [`nettacker/modules/`](../nettacker/modules/).
Use `--show-all-modules` for live metadata and check-specific details.

### Scan modules

| Module | Description |
| --- | --- |
| `admin_scan` | Searches common web paths for exposed administration interfaces. |
| `adobe_aem_lastpatcheddate_scan` | Detects Adobe Experience Manager (AEM) and estimates its last patched date from exposed client-side assets. |
| `citrix_lastpatcheddate_scan` | Detects Citrix NetScaler Gateway and estimates its last patched date. |
| `config_file_scan` | Searches common web paths for accidentally exposed configuration files. |
| `confluence_version_scan` | Identifies an Atlassian Confluence installation and reports its version. |
| `crushftp_lastpatcheddate_scan` | Detects CrushFTP and estimates its last patched date from a published web asset. |
| `cups_version_scan` | Queries the CUPS web interface, normally on port 631, and reports the detected version. |
| `dir_scan` | Searches for common or interesting web directories. |
| `drupal_modules_scan` | Enumerates popular modules installed on a Drupal site. |
| `drupal_theme_scan` | Identifies themes installed on a Drupal site. |
| `drupal_version_scan` | Identifies a Drupal installation and reports its version. |
| `http_html_title_scan` | Extracts the HTML `<title>` element to help identify the application served by a web endpoint. |
| `http_redirect_scan` | Reports HTTP 3xx redirects and their destination locations. |
| `http_status_scan` | Requests a web endpoint and reports its HTTP response status. |
| `icmp_scan` | Uses ICMP echo requests to check whether a target responds and records the response time. |
| `ivanti_csa_lastpatcheddate_scan` | Detects an Ivanti Cloud Services Appliance (CSA) and estimates its last patched date. |
| `ivanti_epmm_lastpatcheddate_scan` | Detects Ivanti Endpoint Manager Mobile (EPMM) and estimates its last patched date from response headers. |
| `ivanti_ics_lastpatcheddate_scan` | Detects Ivanti Connect Secure (ICS) and estimates its last patched date from published assets. |
| `ivanti_vtm_version_scan` | Detects an Ivanti Virtual Traffic Manager (vTM) appliance and reports its version. |
| `jenkins_version_scan` | Detects a Jenkins automation server and reports its version. |
| `joomla_template_scan` | Identifies templates installed on a Joomla site. |
| `joomla_user_enum_scan` | Attempts to enumerate Joomla users through publicly available responses. |
| `joomla_version_scan` | Identifies a Joomla installation and reports its version. |
| `moveit_version_scan` | Detects Progress MOVEit Transfer and reports its version. |
| `pma_scan` | Searches common paths for a phpMyAdmin installation. |
| `port_scan` | Performs TCP connection checks against the selected ports and fingerprints supported services. |
| `smartermail_version_scan` | Detects SmarterMail and extracts version information from its licensing API. |
| `ssl_expiring_certificate_scan` | Reports TLS certificates that have expired or are approaching expiration. |
| `subdomain_scan` | Discovers subdomains using DNS and internet-based data sources; some queries are sent to third-party services. |
| `viewdns_reverse_iplookup_scan` | Uses ViewDNS.info to find domains associated with the target IP address. |
| `waf_scan` | Looks for response characteristics associated with web application firewalls (WAFs). |
| `web_technologies_scan` | Identifies web servers, frameworks, content-management systems, and other web technologies. |
| `wordpress_version_scan` | Detects WordPress and extracts its version from publicly accessible pages. |
| `wp_plugin_scan` | Enumerates popular plugins installed on a WordPress site. |
| `wp_theme_scan` | Identifies themes installed on a WordPress site. |
| `wp_timethumbs_scan` | Searches common WordPress paths for the TimThumb PHP script. |

### Vulnerability modules

Vulnerability results are indicators, not proof that a target is exploitable in every deployment.
Confirm findings manually and consult the references shown by `--show-all-modules` before remediation.
Several modules send exploit-like payloads, execute fixed marker commands, read standard system files,
or use an external callback service. Review a module's YAML template before running it in a sensitive
environment.

| Module | Description |
| --- | --- |
| `accela_cve_2021_34370_vuln` | Probes the Accela Civic Platform logout endpoint for the CVE-2021-34370 open redirect to an external URL. |
| `adobe_coldfusion_cve_2023_26360_vuln` | Probes Adobe ColdFusion for CVE-2023-26360 arbitrary file read by requesting the internal `password.properties` file. |
| `adobe_coldfusion_cve_2026_48282_vuln` | Probes Adobe ColdFusion RDS for CVE-2026-48282 path traversal by attempting to read a standard operating-system file. |
| `aiohttp_cve_2024_23334_vuln` | Checks aiohttp static-file handling for CVE-2024-23334 directory traversal and arbitrary file read. |
| `apache_cve_2021_41773_vuln` | Checks Apache HTTP Server 2.4.49 for CVE-2021-41773 path traversal and file disclosure. |
| `apache_cve_2021_42013_vuln` | Probes Apache HTTP Server 2.4.50 for CVE-2021-42013 path traversal by attempting to read `/etc/passwd`. |
| `apache_ofbiz_cve_2024_38856_vuln` | Probes Apache OFBiz for CVE-2024-38856 by executing `id` through the exposed Groovy program endpoint. |
| `apache_struts_vuln` | Probes Apache Struts for CVE-2017-5638 OGNL injection using a non-destructive response-header marker. |
| `aviatrix_cve_2021_40870_vuln` | Tests Aviatrix Controller for CVE-2021-40870 by writing a PHP `phpinfo()` probe to `random_string1.php` and requesting it; the probe file may remain on a vulnerable target. |
| `cisco_hyperflex_cve_2021_1497_vuln` | Probes the Cisco HyperFlex management interface for CVE-2021-1497 command injection using a `nettacker` response marker. |
| `citrix_cve_2019_19781_vuln` | Probes Citrix ADC and Gateway products for CVE-2019-19781 path traversal by attempting to read `smb.conf`. |
| `citrix_cve_2023_24488_vuln` | Checks Citrix ADC and Gateway products for CVE-2023-24488 cross-site scripting. |
| `citrix_cve_2023_4966_vuln` | Checks NetScaler ADC and Gateway for CVE-2023-4966 information disclosure, commonly known as Citrix Bleed. |
| `clickjacking_vuln` | Reports responses where present `X-Frame-Options` and Content Security Policy headers lack recognized frame restrictions and no recognized HTML policy metadata is found; absent headers are not currently flagged. |
| `cloudron_cve_2021_40868_vuln` | Checks Cloudron login redirects for CVE-2021-40868 reflected cross-site scripting. |
| `confluence_cve_2023_22515_vuln` | Identifies Confluence 8.x build versions in the ranges affected by CVE-2023-22515; it does not attempt to create an administrator. |
| `confluence_cve_2023_22527_vuln` | Probes Confluence for CVE-2023-22527 template injection by executing `id` and returning its output in a response header. |
| `content_security_policy_vuln` | Evaluates the Content Security Policy header and page content for empty or `unsafe-*` policy patterns. |
| `content_type_options_vuln` | Reports a present `X-Content-Type-Options` header whose value does not contain `nosniff`; an absent header is not currently flagged. |
| `crushftp_cve_2025_31161_vuln` | Probes CrushFTP for CVE-2025-31161 by attempting unauthenticated access to the user-list endpoint. |
| `cyberoam_netgenie_cve_2021_38702_vuln` | Checks Cyberoam NetGenie devices for CVE-2021-38702 reflected cross-site scripting. |
| `exponent_cms_cve_2021_38751_vuln` | Checks ExponentCMS for CVE-2021-38751 host-header injection that can produce attacker-controlled links. |
| `f5_cve_2020_5902_vuln` | Checks F5 BIG-IP TMUI for CVE-2020-5902 path traversal and arbitrary file read. |
| `forgerock_am_cve_2021_35464_vuln` | Probes the unauthenticated ForgeRock AM `ccversion` endpoint associated with CVE-2021-35464; it does not send a deserialization payload. |
| `galera_webtemp_cve_2021_40960_vuln` | Checks Galera WebTemplate for CVE-2021-40960 directory traversal and sensitive file disclosure. |
| `geoserver_cve_2024_36401_vuln` | Uses a non-command XPath expression and the resulting exception to identify GeoServer CVE-2024-36401 behavior. |
| `grafana_cve_2021_43798_vuln` | Checks Grafana for CVE-2021-43798 plugin-path traversal and arbitrary file read. |
| `graphql_vuln` | Checks whether a known GraphQL endpoint exposes schema introspection without authentication. |
| `gurock_testrail_cve_2021_40875_vuln` | Checks Gurock TestRail for CVE-2021-40875 sensitive file-list disclosure. |
| `hoteldruid_cve_2021-37833_vuln` | Checks HotelDruid for CVE-2021-37833 reflected cross-site scripting. |
| `http_cookie_vuln` | Examines `Set-Cookie` headers for missing `Secure`, `HttpOnly`, `SameSite`, or `Max-Age` attributes. |
| `http_cors_vuln` | Tests whether the server reflects untrusted origins in `Access-Control-Allow-Origin`, indicating a permissive CORS policy. |
| `http_options_enabled_vuln` | Reports web servers that respond to `OPTIONS` and disclose enabled HTTP methods in the `Allow` header. |
| `ivanti_epmm_cve_2023_35082_vuln` | Checks Ivanti EPMM and MobileIron Core for CVE-2023-35082 authentication bypass. |
| `ivanti_ics_cve_2023_46805_vuln` | Checks Ivanti Connect Secure for CVE-2023-46805 authentication-bypass exposure and mitigation status. |
| `joomla_cve_2023_23752_vuln` | Checks Joomla 4.0.0 through 4.2.7 for CVE-2023-23752 unauthenticated configuration disclosure. |
| `justwirting_cve_2021_41878_vuln` | Checks i-Panel Administration System for CVE-2021-41878 reflected cross-site scripting. |
| `langflow_cve_2025_3248_vuln` | Probes Langflow before 1.3.0 for CVE-2025-3248 by executing code that raises a fixed `Nettacker` exception through the validation endpoint. |
| `log4j_cve_2021_44228_vuln` | Sends Log4Shell JNDI callbacks through multiple HTTP methods and headers, then confirms them through the third-party `log4shell.huntress.com` service. |
| `majordomo_rce_cve_2026_27174_vuln` | Probes MajorDoMo for CVE-2026-27174 by using the unauthenticated PHP console to read `/etc/passwd`. |
| `maxsite_cms_cve_2021_35265_vuln` | Checks MaxSite CMS for CVE-2021-35265 reflected cross-site scripting. |
| `memos_cve_2025_22952_ssrf_vuln` | Checks Memos through version 0.24.0 for CVE-2025-22952 server-side request forgery in link metadata handling. |
| `metabase_cve_2026_72898_vuln` | Uses six-second PostgreSQL and MySQL/MariaDB delay payloads to test Metabase password-reset handling for CVE-2026-72898 SQL injection. |
| `meteobridge_cve_2025_4008_vuln` | Probes MeteoBridge for CVE-2025-4008 command injection by executing `id` through the `templatefile` parameter. |
| `msexchange_cve_2021_26855_vuln` | Checks Microsoft Exchange Server for CVE-2021-26855 ProxyLogon server-side request forgery. |
| `msexchange_cve_2021_34473_vuln` | Probes crafted Exchange Autodiscover paths for response signatures associated with CVE-2021-34473 ProxyShell. |
| `nextjs_cve_2025_55182_vuln` | Probes CVE-2025-55182 React2Shell by executing a fixed arithmetic expression through a Unix shell or PowerShell and checking the redirect marker. |
| `nexus_cve_2024_4956_vuln` | Checks Sonatype Nexus Repository Manager for CVE-2024-4956 unauthenticated path traversal and arbitrary file read. |
| `nginx_ui_cve_2026_33032_vuln` | Checks Nginx UI before 2.3.4 for CVE-2026-33032 unauthenticated access to the MCP message endpoint. |
| `novnc_cve_2021_3654_vuln` | Checks noVNC for CVE-2021-3654 user-controlled open redirects. |
| `omigod_cve_2021_38647_vuln` | Probes Open Management Infrastructure for CVE-2021-38647 by executing the `id` command through WS-Management. |
| `paloalto_globalprotect_cve_2025_0133_vuln` | Checks PAN-OS GlobalProtect gateways and portals for CVE-2025-0133 reflected cross-site scripting. |
| `paloalto_panos_cve_2025_0108_vuln` | Checks PAN-OS management interfaces for CVE-2025-0108 authentication bypass. |
| `payara_cve_2021_41381_vuln` | Checks Payara Micro Community for CVE-2021-41381 directory traversal. |
| `phpinfo_cve_2021_37704_vuln` | Checks phpFastCache vendor paths for CVE-2021-37704 unauthenticated `phpinfo()` disclosure. |
| `placeos_cve_2021_41826_vuln` | Checks PlaceOS Authentication Service for CVE-2021-41826 open redirects. |
| `prestashop_cve_2021_37538_vuln` | Checks the PrestaShop SmartBlog module for CVE-2021-37538 SQL injection. |
| `puneethreddyhc_sqli_cve_2021_41648_vuln` | Checks PuneethReddyHC Online Shopping System for CVE-2021-41648 unauthenticated SQL injection in the `prId` parameter. |
| `puneethreddyhc_sqli_cve_2021_41649_vuln` | Checks PuneethReddyHC Online Shopping System for CVE-2021-41649 unauthenticated SQL injection in the `cat_id` parameter. |
| `qsan_storage_xss_cve_2021_37216_vuln` | Checks QSAN Storage Manager for CVE-2021-37216 unauthenticated reflected cross-site scripting. |
| `server_version_vuln` | Reports version details disclosed by the HTTP `Server` response header. |
| `siyuan_cve_2026_34605_vuln` | Checks SiYuan Note through version 3.6.1 for CVE-2026-34605 reflected SVG cross-site scripting. |
| `smartermail_cve_2026_24423_vuln` | Checks SmarterMail before build 9511 for CVE-2026-24423 unauthenticated command-execution exposure using a non-routable probe. |
| `sonicwall_sslvpn_cve_2024_53704_vuln` | Sends a crafted `swap` cookie to the SonicWall SSL VPN client endpoint and checks for the launcher response associated with CVE-2024-53704. |
| `ssl_certificate_weak_signature_vuln` | Reports TLS certificates signed with weak or deprecated signature algorithms. |
| `ssl_expired_certificate_vuln` | Reports TLS certificates that have expired or are not yet valid. |
| `ssl_self_signed_certificate_vuln` | Reports TLS certificates whose issuer and subject indicate that they are self-signed. |
| `ssl_weak_cipher_vuln` | Reports TLS endpoints that negotiate weak cipher suites. |
| `ssl_weak_version_vuln` | Reports TLS endpoints that support deprecated SSL or TLS protocol versions. |
| `strict_transport_security_vuln` | Reports a present `Strict-Transport-Security` header that omits `max-age` or `includeSubDomains`; the implementation does not flag a completely absent header. |
| `subdomain_takeover_vuln` | Looks for web-response fingerprints associated with unclaimed third-party resources; it does not independently verify DNS records or claimability. |
| `teamcity_cve_2024_27198_vuln` | Checks JetBrains TeamCity before 2023.11.4 for CVE-2024-27198 authentication bypass. |
| `tieline_cve_2021_35336_vuln` | Checks Tieline administration interfaces for CVE-2021-35336 exposure involving default credentials. |
| `tjws_cve_2021_37573_vuln` | Checks Tiny Java Web Server for CVE-2021-37573 reflected cross-site scripting on error pages. |
| `vbulletin_cve_2019_16759_vuln` | Probes vBulletin 5.x for CVE-2019-16759 by executing `id` through a widget template. |
| `vite_cve_2025_31125_vuln` | Checks network-exposed Vite development servers for CVE-2025-31125 arbitrary file disclosure. |
| `wordpress_core_cve_2026_63030_vuln` | Sends a crafted WordPress batch request and checks its multi-status response for CVE-2026-63030 REST API route confusion. |
| `wp_plugin_cve_2021_38314_vuln` | Probes WordPress `admin-ajax.php` for the predictable MD5 response exposed by Redux Framework CVE-2021-38314. |
| `wp_plugin_cve_2021_39316_vuln` | Checks the WordPress ZoomSounds plugin for CVE-2021-39316 directory traversal and arbitrary file download. |
| `wp_plugin_cve_2021_39320_vuln` | Checks the WordPress underConstruction plugin for CVE-2021-39320 reflected cross-site scripting. |
| `wp_plugin_cve_2023_47668_vuln` | Checks the WordPress Restrict Content plugin for CVE-2023-47668 sensitive information exposure through a legacy log file. |
| `wp_plugin_cve_2023_6875_vuln` | Checks whether the WordPress POST SMTP Mailer `connect-app` endpoint returns `fcm_token` without authentication, indicating CVE-2023-6875 exposure; it does not inject JavaScript. |
| `wp_xmlrpc_bruteforce_vuln` | Detects WordPress XML-RPC `wp.getUsersBlogs` behavior that can be used for credential attacks. |
| `wp_xmlrpc_dos_vuln` | Detects exposed WordPress XML-RPC multicall functionality that can amplify requests and contribute to denial of service. |
| `wp_xmlrpc_pingback_vuln` | Detects enabled WordPress XML-RPC pingbacks that can be abused for server-side requests or reflected denial of service. |
| `x_powered_by_vuln` | Reports technology details disclosed by the HTTP `X-Powered-By` response header. |
| `x_xss_protection_vuln` | Reports a present legacy `X-XSS-Protection` header whose value is not `1; mode=block`; an absent header is not currently flagged. |
| `xdebug_rce_vuln` | Detects the Xdebug 2.5.5 response header associated with a remotely exploitable Xdebug release. |
| `zoho_cve_2021_40539_vuln` | Probes the unauthenticated ADSelfService Plus `LogonCustomization` preview action associated with CVE-2021-40539; it does not upload or execute code. |

Some identifiers retain historical filename spellings, such as
`hoteldruid_cve_2021-37833_vuln` and `justwirting_cve_2021_41878_vuln`. Copy identifiers exactly;
renaming them here would make the examples invalid.

### Brute-force modules

| Module | Default port(s) | Description |
| --- | --- | --- |
| `ftp_brute` | 21 | Attempts authenticated logins to an FTP service. |
| `ftps_brute` | 990 | Attempts authenticated logins to an implicit FTPS service. |
| `pop3_brute` | 110 | Attempts authenticated logins to a POP3 mail service. |
| `pop3s_brute` | 995 | Attempts authenticated logins to a POP3 service over TLS. |
| `smb_brute` | 445 | Attempts authenticated logins to an SMB service. |
| `smtp_brute` | 25, 2525 | Attempts authenticated logins to an SMTP service. |
| `smtps_brute` | 25, 2525, 465, 587 | Attempts authenticated logins to SMTP services with TLS support. |
| `ssh_brute` | 22, 2222 | Attempts authenticated logins to an SSH service. |
| `telnet_brute` | 23 | Attempts authenticated logins to a Telnet service that uses conventional login prompts. |


## Brute-force credentials

Unless credentials are supplied, each brute-force module combines every default username in its
YAML template with every entry in the bundled password wordlist:

| Modules | Default usernames |
| --- | --- |
| `ftp_brute`, `ftps_brute` | `root`, `admin`, `user`, `test`, `anonymous` |
| `smb_brute` | `administrator`, `admin`, `root`, `user`, `test`, `guest` |
| `pop3_brute`, `pop3s_brute`, `smtp_brute`, `smtps_brute`, `ssh_brute`, `telnet_brute` | `root`, `admin`, `user`, `test` |

The default password candidates are the 1,000 non-empty values in
[`top_1000_common_passwords.txt`](../nettacker/lib/payloads/passwords/top_1000_common_passwords.txt),
plus an empty password. The loader treats blank lines as entries, so the leading blank line adds the
empty-password attempt and the final newline currently adds a duplicate empty value. The older
short credential list previously shown on this page does not describe the current module templates.

Override the defaults with comma-separated values (`-u`, `-p`) or files containing one value per
line (`-U`, `-P`):

```console
python nettacker.py -i scanme.example -m ssh_brute \
  -U authorized-users.txt -P authorized-passwords.txt
```

Prefer credential files over command-line passwords: command-line values may be retained in shell
history or exposed through process inspection. Be aware of the target's lockout and rate-limit
policies before running a brute-force module.

## Writing your own module

Modules are declarative YAML. See [Developers](Developers.md) for the module template, available libraries and
step/condition reference.
