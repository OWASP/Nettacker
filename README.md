OWASP Nettacker
=========
[![Build Status](https://github.com/OWASP/Nettacker/actions/workflows/ci_cd.yml/badge.svg?branch=master)](https://github.com/OWASP/Nettacker/actions/workflows/ci_cd.yml/badge.svg?branch=master)
[![Apache License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://github.com/OWASP/Nettacker/blob/master/LICENSE)
[![Twitter](https://img.shields.io/badge/Twitter-@iotscan-blue.svg)](https://twitter.com/iotscan)
![GitHub contributors](https://img.shields.io/github/contributors/OWASP/Nettacker)
[![Documentation Status](https://readthedocs.org/projects/nettacker/badge/?version=latest)](https://nettacker.readthedocs.io/en/latest/?badge=latest)
[![repo size ](https://img.shields.io/github/repo-size/OWASP/Nettacker)](https://github.com/OWASP/Nettacker)
[![Docker Pulls](https://img.shields.io/docker/pulls/owasp/nettacker)](https://hub.docker.com/r/owasp/nettacker)


<img src="https://raw.githubusercontent.com/OWASP/Nettacker/master/nettacker/web/static/img/owasp-nettacker.png" width="200"><img src="https://raw.githubusercontent.com/OWASP/Nettacker/master/nettacker/web/static/img/owasp.png" width="500">


**DISCLAIMER**

* ***THIS SOFTWARE WAS CREATED FOR AUTOMATED PENETRATION TESTING AND INFORMATION GATHERING. YOU MUST USE THIS SOFTWARE IN A RESPONSIBLE AND ETHICAL MANNER. DO NOT TARGET SYSTEMS OR APPLICATIONS WITHOUT OBTAINING PERMISSIONS OR CONSENT FROM THE SYSTEM OWNERS OR ADMINISTRATORS. CONTRIBUTORS WILL NOT BE RESPONSIBLE FOR ANY ILLEGAL USAGE.***

![2018-01-19_0-45-07](https://user-images.githubusercontent.com/7676267/35123376-283d5a3e-fcb7-11e7-9b1c-92b78ed4fecc.gif)

OWASP Nettacker project is created to automate information gathering, vulnerability scanning and eventually generating a report for networks, including services, bugs, vulnerabilities, misconfigurations, and other information. This software **will** utilize TCP SYN, ACK, ICMP, and many other protocols in order to detect and bypass Firewall/IDS/IPS devices. By leveraging a unique method in OWASP Nettacker for discovering protected services and devices such as SCADA. It would make a competitive edge compared to other scanners making it one of the best.


* OWASP Page: https://owasp.org/www-project-nettacker/
* Wiki: https://github.com/OWASP/Nettacker/wiki
* Slack: #project-nettacker on https://owasp.slack.com
* Installation: https://github.com/OWASP/Nettacker/wiki/Installation
* Usage: https://github.com/OWASP/Nettacker/wiki/Usage
* GitHub: https://github.com/OWASP/Nettacker
* Docker Image: https://hub.docker.com/r/owasp/nettacker
* How to use the Dockerfile: https://github.com/OWASP/Nettacker/wiki/Installation#docker
* OpenHub: https://www.openhub.net/p/OWASP-Nettacker
* **Donate**: https://owasp.org/donate/?reponame=www-project-nettacker&title=OWASP+Nettacker
* **Read More**: https://www.secologist.com/open-source-projects

____________
Quick Setup & Run
============
```bash
$ docker-compose up -d && docker exec -it nettacker-nettacker-1 /bin/bash
# poetry run python nettacker.py -i owasp.org -s -m port_scan
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

## Adopters

We’re grateful to the organizations, community projects, and individuals who adopt and rely on OWASP Nettacker for their security workflows.

If you’re using OWASP Nettacker in your organization or project, we’d love to hear from you! Feel free to add your details to the [ADOPTERS.md](ADOPTERS.md) file by submitting a pull request or reach out to us via GitHub issues. Let’s showcase how Nettacker is making a difference in the security community!

 See [ADOPTERS.md](ADOPTERS.md) for details.

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

_____________
## Stargazers over time

[![Stargazers over time](https://starchart.cc/OWASP/Nettacker.svg)](https://starchart.cc/OWASP/Nettacker)


