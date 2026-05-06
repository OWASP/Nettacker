---
name: pqc-compliance-scanner
researched: 2026-05-06
incomplete: false
---

# Research Dossier — PQC compliance scanner for OWASP Nettacker

## Market

The buyers are federal contractors, banks, and managed-security-service providers operating under named PQC migration mandates that are now active obligations rather than future ones:

- **US federal civil agencies** under OMB M-23-02 must submit a cryptographic-system inventory **annually on or before May 4 through 2035** to OMB and ONCD; the inventory must focus on High-Value Assets and high-impact systems [^omb-m23-02].
- **US National Security Systems (NSS)** are governed by CNSA 2.0: as of **January 1, 2027 all new NSS acquisitions must be CNSA 2.0 compliant by default**, with full enforcement of CNSA 2.0 across all NSS cryptographic implementations expected by end of 2031 [^cnsa-postquantum] [^cnsa-axelspire].
- **CISA** explicitly published a "Strategy for Migrating to Automated PQC Discovery and Inventory Tools" in September 2024 — i.e. the buyer is on record asking for tools in this exact category [^cisa-pqc-strategy].
- **CISA Product Categories for Technologies That Use Post-Quantum Cryptography Standards** was published **January 23, 2026**, advising agencies to prioritize PQC-capable products in acquisition planning [^postquantum-us-2026].

Proxy spend: pen-test budgets at federal contractors plus the operational budget that funds annual cryptographic-inventory exercises. Nettacker is OSS, so the play is adoption and ecosystem positioning, not licensing.

## Direct competitors

| Name | Price | Key feature | Gap vs our wedge |
|---|---|---|---|
| **pqcscan** (Anvil Secure) [^pqcscan-github] [^pqcscan-helpnet] | Free, BSD-2-Clause, Rust binary | Dedicated SSH + TLS PQC scanner; JSON output → HTML report; multi-host parallel scan | Standalone CLI — no integration into a broader scanner platform; no historical drift, no CI gating, no Web UI/API. Excludes "experimental" TLS algorithms by default. |
| **PQC-Scanner** (cyberjez) [^pqc-scanner-cyberjez] | Free OSS, Python + Win exe | Scans TLS certificates for quantum-vulnerable signatures (RSA/ECDSA chains) | Focuses on cert chain, not on KEX/named-groups — it answers a different question. Complementary, not overlapping with our wedge. |
| **testssl.sh** [^testssl-issue-2960] | Free OSS (GPL) | Reports ML-KEM / X25519MLKEM768 if the underlying OpenSSL build supports them | Silent when server has no PQC — explicit "PQC missing" reporting is an open feature request (Issue #2960, still open as of 2026-05). Depends on the local OpenSSL build; can't probe groups its OpenSSL doesn't know about. |
| **PQScan / pqscan.io** [^pqscan-io] | SaaS (free tier) | Browser-based "is this site PQC-ready" check | SaaS-only — won't help operators scan internal/non-public endpoints; no API integration with a CI pipeline; no SSH scanning. |
| **Palo Alto Networks PAN-OS PQC Detection & Control** [^paloalto-pqc] | Commercial (NGFW license) | Inline PQC detection and policy enforcement on enterprise traffic | Tied to PAN-OS firewalls; an enforcement product, not an external/blackbox endpoint scanner. Different deployment model. |

The closest direct competitor is **pqcscan**. Our differentiation is **integration into Nettacker's existing module/library/Web-UI/API/drift-detection platform** rather than a standalone binary.

## Adjacent tools

| Name | Why adjacent, not direct | Can they pivot into us? |
|---|---|---|
| **sslyze** [^sslyze-github] | Has `ELLIPTIC_CURVES` scan command and a mature Python TLS library (uses nassl which wraps a custom OpenSSL). No PQC named-group scan command documented as of 2026-05. | Yes — a `POST_QUANTUM_GROUPS` scan command is a natural addition to its plugin model. If they ship it first, our wedge's differentiation collapses to "Nettacker integration." |
| **Qualys SSL Labs** [^ssllabs-issue-986] | Public TLS posture grader. Does not list PQC named groups in "Supported Named Groups" output as of 2026-05 (Issue #986 open). Only scans HTTPS, not SSH. | Yes — they have the data pipeline, but pivoting takes a release cycle. |
| **Cloudflare Radar / Internet Measurement** [^cloudflare-pq-2025] | Reports aggregate PQ adoption (>60% of human HTTPS traffic on Cloudflare uses hybrid ML-KEM by 2025). | No — they measure aggregate traffic, not per-endpoint posture for an operator. |
| **OpenSSL 3.5+ `openssl s_client -groups`** [^openssl-3-5-pqc] | Native ML-KEM and X25519MLKEM768 support since OpenSSL 3.5.0 (April 2025). | This is a building block, not a product. It is what teams currently script around — i.e. our user's status-quo workaround. |

## Technical prior art

- **Open Quantum Safe (liboqs / oqsprovider)** — reference implementation of post-quantum primitives plus an OpenSSL 3 provider. The "heavy" path Approach B in the idea doc would build on. URL: https://github.com/open-quantum-safe/oqs-provider [^pqcscan-helpnet].
- **draft-ietf-tls-mlkem-07** — IETF spec defining ML-KEM-512/768/1024 as TLS 1.3 NamedGroups with codepoints `0x0200`, `0x0201`, `0x0202`. Most recent revision Feb 2026; intended status Standards Track [^ietf-mlkem-07].
- **draft-ietf-tls-ecdhe-mlkem-04** — IETF spec for hybrid `X25519MLKEM768` (codepoint `0x11EC` / 4588), `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`. Most recent revision Feb 2026; expires Aug 2026; final RFC expected 2026-2027 [^ietf-ecdhe-mlkem].
- **draft-ietf-sshm-mlkem-hybrid-kex-10** — IETF spec for ML-KEM-based hybrid SSH KEX [^ietf-sshm-mlkem].
- **OpenSSH 9.0/9.9/10.0/10.1 release pages** [^openssh-pq] — authoritative source for `sntrup761x25519-sha512@openssh.com` (added 9.0, default 9.0–9.9), `mlkem768x25519-sha256` (added 9.9, default since 10.0, April 2025), and OpenSSH 10.1's `WarnWeakCrypto` behaviour.
- **eprint.iacr.org/2026/834** — "Detecting Post-Quantum and Hybrid TLS Deployments via Raw TLS Record Inspection" — direct prior art for our exact technique: raw ClientHello observation without a complete handshake [^eprint-tls-record].
- **NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)** — finalized and effective **2024-08-14** [^nist-fips-final] [^nist-pqc-news].

## Regulatory / legal

- **OMB M-23-02 / NSM-10** (US federal civil agencies): annual cryptographic inventory through 2035, deadline May 4 each year. A scanner that automates discovery directly satisfies the inventory obligation [^omb-m23-02] [^nsm-10-presentation].
- **CNSA 2.0** (US NSS): all new NSS acquisitions CNSA-2.0-compliant by default from **2027-01-01**; full enforcement by end of 2031. Approved algorithms: AES-256, ML-KEM-1024, ML-DSA-87, SHA-384/512 [^cnsa-postquantum].
- **CISA Automated PQC Discovery and Inventory Tools strategy** (Sept 2024): explicit federal-level endorsement of the tool category Nettacker would compete in [^cisa-pqc-strategy].
- **NIST FIPS 140-2 → 140-3 transition**: as of **2026-09-21** all FIPS 140-2 certificates move to Historical status; federal procurement requires FIPS 140-3 validated modules [^postquantum-us-2026]. *Not* a constraint on a scanner that doesn't itself perform regulated cryptographic operations — we observe, we don't encrypt.
- **OWASP Apache-2.0 license** (Nettacker repo's `LICENSE`): no conflict with any source-of-truth IETF / NIST / IANA reference material we'd build against. pqcscan's BSD-2-Clause is also Apache-2.0 compatible if we need to read their algorithm-name lists for cross-checking — though we will derive the lists from primary sources (IETF drafts, OpenSSH release notes), not from pqcscan code.
- **Scanning legality**: Nettacker is a pen-test tool and the README already carries the "scan only assets you are authorized to test" disclaimer. PQC scanning inherits this norm — no additional legal layer.

## Open questions that research did not answer

- **Q4 from the idea doc — load-balancer crash precedents**: web search did not surface a specific incident of a TLS 1.3 ClientHello with PQC `supported_groups` crashing F5 BIG-IP, Citrix Netscaler, or AWS ALB. F5 has had TMM crashes related to TLS processing historically (e.g. malformed packet handling), and FFDHE-group handshake issues have been documented [^f5-handshake-failures], but no PQC-specific incident was found. Treat absence-of-evidence as weak signal; encode the conservative rule "ClientHello is strictly RFC 8446 / RFC-draft-aligned, single connection per probe, never fragment" as a design invariant anyway.
- **Q7 from the idea doc — Nettacker module YAML support for multi-valued verdict enums**: search of repo + general queries did not give a definitive answer. This is a repo-internal question — to be resolved by reading `nettacker/core/lib/base.py` and `nettacker/core/module.py` during `/slo-architect`, not by web research.
- **sslyze PQC roadmap**: no public roadmap statement found about whether sslyze plans to add a `POST_QUANTUM_GROUPS` scan command. Treat as a non-blocking competitive risk and revisit at v1.0 GA.
- **Future SSH PQ signature algorithms**: openssh.org/pq.html says "OpenSSH will add support for post-quantum signature algorithms in the future" but no specific algorithm names. Defer signature-side scanning to v2.

[^omb-m23-02]: OMB M-23-02 "Migrating to Post-Quantum Cryptography" (2022-11-18). https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf
[^cnsa-postquantum]: "NSA Unveils CNSA 2.0 Post-Quantum Algorithm Suite". https://postquantum.com/quantum-policy/nsa-cnsa-2-0-pqc/
[^cnsa-axelspire]: "Post-Quantum Cryptography Timeline & Mandates". https://axelspire.com/business/pqc-timeline-mandates/
[^cisa-pqc-strategy]: CISA "Strategy for Migrating to Automated Post-Quantum Cryptography Discovery and Inventory Tools" (Sept 2024). https://www.cisa.gov/sites/default/files/2024-09/Strategy-for-Migrating-to-Automated-PQC-Discovery-and-Inventory-Tools.pdf
[^postquantum-us-2026]: "The Complete US Post-Quantum Cryptography (PQC) Regulatory Framework in 2026". https://postquantum.com/quantum-policies/us-pqc-regulatory-framework-2026/
[^pqcscan-github]: pqcscan repository. https://github.com/anvilsecure/pqcscan
[^pqcscan-helpnet]: "pqcscan: Open-source post-quantum cryptography scanner" (Help Net Security, 2025-07-14). https://www.helpnetsecurity.com/2025/07/14/pqcscan-open-source-post-quantum-cryptography-scanner/
[^pqc-scanner-cyberjez]: "PQC-Scanner". https://github.com/cyberjez/PQC-Scanner
[^testssl-issue-2960]: testssl.sh Issue #2960 "[Feature request] TestSSL pointing out missing support for PQC/KEM (NIST FIPS 203)". https://github.com/testssl/testssl.sh/issues/2960
[^pqscan-io]: PQScan SaaS. https://pqscan.io/
[^paloalto-pqc]: Palo Alto Networks "Post-Quantum Cryptography Detection and Control". https://docs.paloaltonetworks.com/network-security/decryption/administration/post-quantum-cryptography-decryption/detection-control-post-quantum-cryptography
[^sslyze-github]: SSLyze repository. https://github.com/nabla-c0d3/sslyze
[^ssllabs-issue-986]: ssllabs-scan Issue #986 "Post-Quantum ciphers are not detected". https://github.com/ssllabs/ssllabs-scan/issues/986
[^cloudflare-pq-2025]: Cloudflare "State of the post-quantum Internet in 2025". https://blog.cloudflare.com/pq-2025/
[^openssl-3-5-pqc]: "OpenSSL 3.5 Post-Quantum Lab: ML-KEM & ML-DSA on RHEL 9.6". https://www.cryptomathic.com/blog/quantum-ready-cryptography-with-openssl-3.5-on-rhel-9.6
[^ietf-mlkem-07]: draft-ietf-tls-mlkem-07. https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/
[^ietf-ecdhe-mlkem]: draft-ietf-tls-ecdhe-mlkem-04. https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
[^ietf-sshm-mlkem]: draft-ietf-sshm-mlkem-hybrid-kex-10. https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/
[^openssh-pq]: OpenSSH "Post-Quantum Cryptography". https://www.openssh.org/pq.html
[^eprint-tls-record]: "Detecting Post-Quantum and Hybrid TLS Deployments via Raw TLS Record Inspection". https://eprint.iacr.org/2026/834
[^nist-fips-final]: NIST FIPS 203 (final). https://csrc.nist.gov/pubs/fips/203/final
[^nist-pqc-news]: "NIST Releases First 3 Finalized Post-Quantum Encryption Standards" (2024-08-13). https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
[^nsm-10-presentation]: NIST CSRC "NSM-10 and the Transition to Post-Quantum Cryptography" (April 2024). https://csrc.nist.gov/csrc/media/Presentations/2024/u-s-government-s-transition-to-pqc/images-media/presman-govt-transition-pqc2024.pdf
[^f5-handshake-failures]: F5 K39580786 "Configure the SSL profile to allow TLS 1.2 and 1.3 only" and related FFDHE-handshake notes. https://my.f5.com/manage/s/article/K39580786
