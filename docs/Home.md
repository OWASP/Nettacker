## Introduction

OWASP Nettacker is an automated penetration testing framework designed to help cyber security professionals and ethical hackers perform reconnaissance, vulnerability assessments, and network security audits efficiently.

Nettacker automates information gathering, vulnerability scanning, and credential brute forcing tasks, making it a powerful tool for identifying weaknesses in networks, web applications, IoT devices and APIs.

OWASP Nettacker is an open-source software written in Python language. OWASP Nettacker uses YAML files to define **modules** in a structured and human-readable format. 

OWASP Nettacker's modular architecture is one of its core strengths, allowing users to perform specific tasks by leveraging a range of pre-built and customizable modules.

By leveraging a modular framework, Nettacker supports multiple protocols and scanning methods, making it highly adaptable to various security testing scenarios.

## Key Features

1. Multi-Protocol Support  
   OWASP Nettacker can scan a wide range of protocols, including HTTP/HTTPS, FTP, SSH, SMTP, ICMP, TELNET, XML-RPC and more.   
   This flexibility allows users to assess diverse systems and applications effectively.  
2. Automation of Information Gathering Security Tests  
   With Nettacker, users can automate reconnaissance, port scanning, vulnerability detection, and brute forcing workflows, minimizing the time and effort required for manual security testing.  
3. Modular and Scalable   
    Its modular design enables users to customize and extend functionality by adding new modules for specific tasks. Nettacker can scale from small, targeted security assessments to large, enterprise-wide scans.  
4. Built-In Port Scanner and Subdomain Enumeration module   
   Nettacker includes powerful Built-In Port Scanner and Subdomain Enumeration modules that streamline the initial stages of penetration testing. The Port Scanner module automatically identifies open ports on target systems, providing valuable insights into the services and potential attack surfaces exposed by a system. This is crucial for mapping a network and targeting specific services during vulnerability assessments. The Subdomain Enumeration module helps uncover hidden subdomains within a domain, which can be critical for identifying additional attack vectors or overlooked assets. Together, these built-in modules simplify the reconnaissance phase, helping security professionals gather key information efficiently before moving on to more advanced testing.  
5. Multi-Format Reporting  
   The tool generates scan reports in multiple formats, including HTML, JSON, CSV and text. Nettacker’s ability to generate reports in JSON and CSV formats offers significant advantages. JSON provides a structured, machine-readable format that is easily parsed and integrated with other tools or systems, making it ideal for automated processing, data analysis, and integration with custom workflows. CSV, on the other hand, offers a simple, tabular format that is easy to read and process using spreadsheets or other data analysis tools. These formats make it easy to analyze findings and share results with stakeholders.  
6. Built-in Database  
   Nettacker includes a built-in database for storing scan results. This ensures data persistence, allowing users to track past assessments, easily search and retrieve previous data from scan results, and generate reports for audit and compliance purposes  
6. The Web UI and API provide enhanced user interaction and integration capabilities. The Web UI offers a user-friendly interface for configuring scans, visualizing results, andsearching the scan data, making Nettacker accessible to both technical and less-technical users. The API allows for programmatic access, enabling automation and integration with third-party tools, CI/CD pipelines, and custom applications. 


## Links

* OWASP Nettacker Project Page: [https://www.owasp.org/nettacker](https://www.owasp.org/nettacker)
* GitHub Repo: [https://github.com/OWASP/Nettacker](https://github.com/OWASP/Nettacker)
* Official Docker Image: [https://hub.docker.com/r/owasp/nettacker/](https://hub.docker.com/r/owasp/nettacker/)
* Slack: **#project-nettacker** on https://owasp.slack.com  (get OWASP Slack invite at https://owasp.org/slack/invite)

* OpenHub: [https://www.openhub.net/p/OWASP-Nettacker](https://www.openhub.net/p/OWASP-Nettacker)
* CI: [https://github.com/OWASP/Nettacker/actions](https://github.com/OWASP/Nettacker/actions)
* **Donate to support this project**: [https://www.owasp.org/](https://owasp.org/donate/?reponame=www-project-nettacker&title=OWASP+Nettacker)
* Original Creator/Maintainer: [https://www.secologist.com/](https://www.secologist.com/)
