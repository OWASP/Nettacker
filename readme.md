OWASP Nettacker
=========
[![Build Status](https://github.com/OWASP/Nettacker/workflows/CI/badge.svg?branch=master)](https://github.com/OWASP/Nettacker/actions/workflows/CI.yml)
[![Apache License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://github.com/OWASP/Nettacker/blob/master/LICENSE)
[![Twitter](https://img.shields.io/badge/Twitter-@iotscan-blue.svg)](https://twitter.com/iotscan)
![GitHub contributors](https://img.shields.io/github/contributors/OWASP/Nettacker)
[![repo size ](https://img.shields.io/github/repo-size/OWASP/Nettacker)](https://github.com/OWASP/Nettacker)


<img src="https://raw.githubusercontent.com/zdresearch/OWASP-Nettacker/master/web/static/img/owasp-nettacker.png" width="200"><img src="https://raw.githubusercontent.com/zdresearch/OWASP-Nettacker/master/web/static/img/owasp.png" width="500">


**DISCLAIMER**

* ***THIS SOFTWARE WAS CREATED FOR AUTOMATED PENETRATION TESTING AND INFORMATION GATHERING. CONTRIBUTORS WILL NOT BE RESPONSIBLE FOR ANY ILLEGAL USAGE.***

![2018-01-19_0-45-07](https://user-images.githubusercontent.com/7676267/35123376-283d5a3e-fcb7-11e7-9b1c-92b78ed4fecc.gif)

OWASP Nettacker project is created to automate information gathering, vulnerability scanning and eventually generating a report for networks, including services, bugs, vulnerabilities, misconfigurations, and other information. This software **will** utilize TCP SYN, ACK, ICMP, and many other protocols in order to detect and bypass Firewall/IDS/IPS devices. By leveraging a unique method in OWASP Nettacker for discovering protected services and devices such as SCADA. It would make a competitive edge compared to other scanner making it one of the bests.


* OWASP Page: https://owasp.org/www-project-nettacker/
* Wiki: https://github.com/OWASP/Nettacker/wiki
* Installation: https://github.com/OWASP/Nettacker/wiki/Installation
* Usage: https://github.com/OWASP/Nettacker/wiki/Usage
* GitHub: https://github.com/OWASP/Nettacker
* Slack: #project-nettacker on https://owasp.slack.com
* Mailing List: https://groups.google.com/forum/#!forum/owasp-nettacker
* Docker Image: https://hub.docker.com/r/alirazmjoo/owaspnettacker/
* How to use the Dockerfile: https://github.com/OWASP/Nettacker/wiki/Installation#docker
* OpenHub: https://www.openhub.net/p/OWASP-Nettacker
* **Donate**: https://owasp.org/donate/?reponame=www-project-nettacker&title=OWASP+Nettacker

____________
Quick Setup & Run
============
```bash
$ docker-compose up -d && docker exec -it nettacker_nettacker_1 /bin/bash
# python nettacker.py -i owasp.org -s -m port_scan
```
* Results are accessible from your (https://localhost:5000) or https://nettacker-api.z3r0d4y.com:5000/ (pointed to your localhost)
* The local database is `.data/nettacker.db` (sqlite).
* Default results path is `.data/results`
* `docker-compose` will share your nettacker folder, so you will not lose any data after `docker-compose down`
* To see the API key in you can run `docker logs nettacker_nettacker_1`.
* More details and setup without docker https://github.com/OWASP/Nettacker/wiki/Installation
_____________
Thanks to our awesome contributors
============
![Awesome Contributors](https://contrib.rocks/image?repo=OWASP/Nettacker)
_____________

## ***IoT Scanner***
*	Python Multi Thread & Multi Process Network Information Gathering Vulnerability Scanner
*	Service and Device Detection ( SCADA, Restricted Areas, Routers, HTTP Servers, Logins and Authentications, None-Indexed HTTP, Paradox System, Cameras, Firewalls, UTM, WebMails, VPN, RDP, SSH, FTP, TELNET Services, Proxy Servers and Many Devices like Juniper, Cisco, Switches and many more… ) 
*	Asset Discovery & Network Service Analysis
*	Services Brute Force Testing
*	Services Vulnerability Testing
*	HTTP/HTTPS Crawling, Fuzzing, Information Gathering and … 
*	HTML, JSON, CSV and Text Outputs
* API & WebUI
*	This project is at the moment in research and development phase 
* Thanks to Google Summer of Code Initiative and all the students who contributed to this project during their summer breaks: 


<img src="https://betanews.com/wp-content/uploads/2016/03/vertical-GSoC-logo.jpg" width="200"></img>

