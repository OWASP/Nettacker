# Security Policy

At OWASP Nettacker, we take security seriously. This document outlines our security policy, including how to report vulnerabilities, our responsible disclosure process, and how we handle security issues.

---

## **Supported Versions**

We provide security updates for the following versions of OWASP Nettacker:

- **Latest Release**: The most recent stable release.
- **Current Master Branch**: The latest development version on the `master` branch.

Older versions may not receive security updates. We strongly recommend that users upgrade to the latest version.

---

## **Reporting a Vulnerability**

If you discover a security vulnerability in OWASP Nettacker, we appreciate your help in disclosing it responsibly. Here’s how you can report it:

### **1. Private Disclosure**
- **Do not** open a public issue for security vulnerabilities.
- Include the following details in your report:
  - A **clear description** of the vulnerability.
  - **Steps to reproduce** the issue (e.g., code snippets, proof of concept).
  - The **affected version(s)** of OWASP Nettacker.
  - Any **potential impact** of the vulnerability (e.g., data exposure, remote code execution).

### **2. GitHub Security Advisory**
- If you prefer, you can also report the vulnerability by creating a **GitHub Security Advisory**:
  - Go to the [OWASP Nettacker repository](https://github.com/OWASP/Nettacker).
  - Click on **Security** > **Report a vulnerability**.
  - Follow the prompts to submit a **private security advisory**.

### **3. Responsible Disclosure Process**
- We will acknowledge your report and work with you to establish a timeline for addressing the vulnerability.
- Once the issue is fixed, we will release a patch and publicly disclose the vulnerability, crediting you (unless you prefer to remain anonymous).

---

## **Vulnerability Handling Process**

1. **Triage**: Our security team will review the report and assess the severity of the vulnerability.
2. **Fix Development**: We will develop and test a fix for the vulnerability.
3. **Release**: We will release a patched version of OWASP Nettacker.
4. **Disclosure**: We will publicly disclose the vulnerability, including credits to the reporter.

---

## **Contacting Maintainers**

For general inquiries or non-security-related issues, you can contact the project leaders:

- **Project Page**: [OWASP Nettacker Project Page](https://owasp.org/nettacker)
- **GitHub Issues**: [OWASP Nettacker Issues](https://github.com/OWASP/Nettacker/issues)
- **Slack/Discord**: Join the OWASP Slack workspace and find us in the `#nettacker` channel.

For **security-related issues**, please use the private disclosure methods described above.

---

## **Security Best Practices for Contributors**

If you are contributing to OWASP Nettacker, please follow these security best practices:

- **Code Review**: All code changes should be reviewed for security issues before merging.
- **Dependencies**: Keep dependencies up-to-date and review them for known vulnerabilities.
- **Testing**: Write tests to ensure that security fixes are effective and do not introduce regressions.
- **Documentation**: Document security-related changes and updates in the `SECURITY.md` file.

---

## **Policy Updates**

This security policy may be updated from time to time. The latest version will always be available in this `SECURITY.md` file.

---

## **Resources**

- [OWASP Nettacker Documentation](https://github.com/OWASP/Nettacker/wiki)
- [OWASP Project Page](https://owasp.org/nettacker)
- [CVE Database](https://cve.mitre.org/)
- [GitHub Security Lab](https://securitylab.github.com/)
