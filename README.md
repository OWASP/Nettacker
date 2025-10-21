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

OWASP Nettacker is an open-source, Python-based automated penetration testing and information-gathering framework designed to help cyber security professionals and ethical hackers perform reconnaissance, vulnerability assessments, and network security audits efficiently. Nettacker automates tasks like port scanning, service detection, subdomain enumeration, network mapping, vulnerability scanning, credential brute-force testing making it a powerful tool for identifying weaknesses in networks, web applications, IoT devices and APIs.

### Key Features

- **Modular architecture** - Each task — like port scanning, directory discovery, subdomain enumeration, vulnerability checks, or credential brute-forcing - is implemented as its own module, giving you control over what runs.
- **Multi-protocol & multithreaded scanning** - Supports HTTP/HTTPS, FTP, SSH, SMB, SMTP, ICMP, TELNET, XML-RPC, and can run scans in parallel for speed.
- **Comprehensive output** - Export reports in HTML, JSON, CSV, and plain text.
- **Built-in database & drift detection** - Stores past scans in the database for easy search and comparison with current results: useful to detect new hosts, open ports, or vulnerabilities in CI/CD pipelines.
- **CLI, REST API & Web UI** - Offers both programmatic integration and a user-friendly web interface for defining scans and viewing results.
- **Evasion techniques** - Enables configurable delays, proxy support, and randomized user-agents to reduce detection by firewalls or IDS systems.
- **Flexible targets** - Accepts single IPv4s, IP ranges, CIDR blocks, domain names, and full HTTP/HTTPS URLs. Targets can be mixed in a single command or loaded from a file using the `-l/--targets-list` flag. 

### Use Cases

- **Penetration Testing**  
  Automate reconnaissance, misconfiguration checks, service discovery, and vulnerability scanning to support efficient and repeatable penetration testing workflows.  

- **Recon & Vulnerability Assessment**  
  Map live hosts, open ports, services, default credentials, and directories, then perform credential brute-forcing or fuzzing using built-in or custom wordlists.
  
- **Attack Surface Mapping**  
  Discover exposed hosts, ports, subdomains, and services quickly using built-in enumeration modules—ideal for both internal and external assets.  

- **Bug Bounty Recon**  
  Automate and scale common reconnaissance tasks like subdomain enumeration, directory brute-forcing, and default credential checks to speed up finding targets.  

- **Network Vulnerability Scanning**  
  Efficiently scan IPs, IP ranges, or entire CIDR blocks or all subdmains of the organisation in parallel using a modular, multithreaded approach for large-scale network assessments.  

- **Shadow IT & Asset Discovery**  
  Use historical scan data and drift detection to uncover unmanaged or forgotten hosts, open ports/services, and subdomains appearing over time.  

- **CI/CD & Compliance Monitoring**  
  Integrate Nettacker into pipelines to track infrastructure changes and detect new vulnerabilities via stored scan history and comparison features.  

### Links

* OWASP Nettacker Project Home Page: https://owasp.org/nettacker
* Documentation: https://nettacker.readthedocs.io
* Slack: [#project-nettacker](https://owasp.slack.com/archives/CQZGG24FQ) on https://owasp.slack.com 
* Installation: https://nettacker.readthedocs.io/en/latest/Installation
* Usage: https://nettacker.readthedocs.io/en/latest/Usage
* GitHub repo: https://github.com/OWASP/Nettacker
* Docker Image: https://hub.docker.com/r/owasp/nettacker
* How to use the Dockerfile: https://nettacker.readthedocs.io/en/latest/Installation/#install-nettacker-using-docker
* OpenHub: https://www.openhub.net/p/OWASP-Nettacker
* **Donate**: https://owasp.org/donate/?reponame=www-project-nettacker&title=OWASP+Nettacker
* **Read More**: https://www.secologist.com/open-source-projects

____________
Quick Setup & Run
============
### CLI (Docker)
```bash

# Basic port scan on a single IP address:
$ docker run owasp/nettacker -i 192.168.0.1 -m port_scan
# Scan the entire Class C network for any devices with port 22 open:
$ docker run owasp/nettacker -i 192.168.0.0/24 -m port_scan -g 22
# Scan all subdomains of 'owasp.org' for http/https services and return HTTP status code
$ docker run owasp/nettacker -i owasp.org -d -s -m http_status_scan
# Display Help
$ docker run owasp/nettacker --help


```
### Web UI (Docker)

```bash
$ docker-compose up 
```
* Use the API Key displayed in the CLI to login to the Web GUI
* Web GUI is accessible from your (https://localhost:5000) or https://nettacker-api.z3r0d4y.com:5000/ (pointed to your localhost)
* The local database is `.nettacker/data/nettacker.db` (sqlite).
* Default results path is `.nettacker/data/results`
* `docker-compose` will share your nettacker folder, so you will not lose any data after `docker-compose down`
* To see the API key in you can also run `docker logs nettacker_nettacker`.
* More details and install without docker https://nettacker.readthedocs.io/en/latest/Installation
_____________
Thanks to our awesome contributors!
============

OWASP Nettacker is an open-source project, built on the principles of collaboration and shared knowledge. The vibrant OWASP community contributes to its development, ensuring that the tool remains up-to-date, adaptable, and aligned with the latest security practices. Thanks to all our awesome contributors! 🚀

![Awesome Contributors](https://contrib.rocks/image?repo=OWASP/Nettacker)

## Adopters

We’re grateful to the organizations, community projects, and individuals who adopt and rely on OWASP Nettacker for their security workflows.

If you’re using OWASP Nettacker in your organization or project, we’d love to hear from you! Feel free to add your details to the [ADOPTERS.md](ADOPTERS.md) file by submitting a pull request or reach out to us via GitHub issues. Let’s showcase how Nettacker is making a difference in the security community!

 See [ADOPTERS.md](ADOPTERS.md) for details.

_____________

## ***Google Summer of Code (GSoC) Project***
*	☀️ OWASP Nettacker Project is participating in the Google Summer of Code Initiative 
* 🙏 Thanks to Google Summer of Code Initiative and all the students who contributed to this project during their summer breaks: 


<a href="https://summerofcode.withgoogle.com"><img src="https://betanews.com/wp-content/uploads/2016/03/vertical-GSoC-logo.jpg" width="200"></img></a>

_____________
## Stargazers over time

[![Stargazers over time](https://starchart.cc/OWASP/Nettacker.svg)](https://starchart.cc/OWASP/Nettacker)

<img alt="" referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=8e922d16-445a-4c63-b4cf-5152fbbaf7fd" />
