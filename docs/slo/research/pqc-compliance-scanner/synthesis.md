---
name: pqc-compliance-scanner
synthesized: 2026-05-06
---

# Synthesis — what this means for the design

## The wedge survives contact with the market

The competitive picture confirms the idea-doc bet. As of 2026-05 the dedicated-PQC-scanner space has exactly one substantive open-source competitor (pqcscan, Anvil Secure, Rust, BSD-2), one cert-focused tool (PQC-Scanner, cyberjez), one SaaS (PQScan), and one inline-NGFW product (Palo Alto). Mature general TLS scanners — testssl.sh, sslyze, Qualys SSL Labs — have not yet shipped first-class PQC posture reporting (testssl.sh Issue #2960, ssllabs-scan Issue #986). **The design must ship a Nettacker-native module rather than vendoring pqcscan because Nettacker's value-add is the pre-existing module/library/Web-UI/API/drift-diff platform — pqcscan has none of that, and writing a pqcscan plugin would split the data model** (source: pqcscan README at https://github.com/anvilsecure/pqcscan; testssl Issue #2960 at https://github.com/testssl/testssl.sh/issues/2960).

## Authoritative algorithm-name sources are stable enough to encode now

For the SSH side, OpenSSH's own `pq.html` is unambiguous: `sntrup761x25519-sha512@openssh.com` (default 9.0–9.9, April 2022) and `mlkem768x25519-sha256` (default since 10.0, April 2025) are the two production algorithm strings, and OpenSSH 10.1 actively warns the user when neither is selected. **The design must hardcode these two algorithm strings as the v1 SSH PQC allowlist and treat additions as a periodic curation task, not a discovery problem, because the OpenSSH project itself only ships these two as of 2026-05** (source: https://www.openssh.org/pq.html).

For the TLS side, IANA's TLS Supported Groups registry has assigned codepoints for ML-KEM-512 (`0x0200`), ML-KEM-768 (`0x0201`), ML-KEM-1024 (`0x0202`) per draft-ietf-tls-mlkem-07, and for the hybrids `X25519MLKEM768` (`0x11EC` / 4588), `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` per draft-ietf-tls-ecdhe-mlkem-04. **The design must encode these as a versioned table in the YAML module rather than fetched at runtime, because the codepoints are stable in IANA registry but the IETF drafts themselves don't reach RFC until 2026-2027 and we cannot assume online lookup is available in air-gapped scan environments** (sources: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/, https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/, IETF tls@ietf.org list at https://www.mail-archive.com/tls@ietf.org/msg19468.html).

## Raw-bytes ClientHello is documented prior art

eprint.iacr.org/2026/834 ("Detecting Post-Quantum and Hybrid TLS Deployments via Raw TLS Record Inspection") establishes that raw TLS record inspection — observing what the server sends back to a probe ClientHello, without completing a handshake — is an established, peer-reviewed approach to PQC posture detection. **The design must implement TLS 1.3 ClientHello probing in pure Python (struct + socket), validate ServerHello / HelloRetryRequest / Alert response shapes, and never complete the handshake, because the academic technique already exists, validates, and lets us avoid both the oqsprovider dep and the connection-completion side effect** (source: https://eprint.iacr.org/2026/834).

## OpenSSH 9.9+ KEXINIT is readable without a custom client

The SSH protocol's MSG_KEXINIT (RFC 4253 §7.1) is sent by the server *before* any negotiation completes — the server unconditionally advertises its full kex_algorithms / host_key_algorithms / encryption_algorithms_client_to_server / encryption_algorithms_server_to_client name-lists. **The design must read SSH KEXINIT directly from the wire (TCP open, send SSH-2.0 client banner, parse exactly one MSG_KEXINIT packet, send disconnect) rather than driving paramiko, because paramiko's high-level `Transport` abstracts away the advertisement view we want and silently negotiates regardless of PQC** (source: RFC 4253 §7.1; OpenSSH PQ documentation at https://www.openssh.com/pq.html).

## Compliance framing is the wedge's marketing copy

OMB M-23-02 mandates federal agencies submit a cryptographic-system inventory annually on or before May 4 through 2035. CNSA 2.0 makes new NSS acquisitions PQC-default from 2027-01-01. CISA's September 2024 strategy explicitly endorses "automated PQC discovery and inventory tools." **The design must emit a `verdict` field with a small enum (`pqc_ready`, `hybrid_only`, `classical_only`, `unknown`) and a `compliance_notes` field that names the framework when the verdict triggers a flag (e.g., `classical_only` against an SSH endpoint = "fails OpenSSH 10.1 WarnWeakCrypto baseline"), because the buyer reads the output to fill an inventory template, not to read raw cipher names** (sources: https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf; https://www.cisa.gov/sites/default/files/2024-09/Strategy-for-Migrating-to-Automated-PQC-Discovery-and-Inventory-Tools.pdf).

## Safety: the absence of a documented LB-crash incident is not the same as proof of safety

Web search did not find a specific case of a PQC-named-group ClientHello crashing F5 BIG-IP, Citrix Netscaler, or AWS ALB. F5 has documented historical TMM crashes from malformed packet handling and FFDHE-handshake issues. **The design must (a) send only RFC-compliant ClientHello shapes, (b) cap connections-per-target-per-run at one per probed group, (c) provide a `--no-pqc-probe` opt-out at the YAML-module level so an operator who has been bitten can disable just the active probing without losing the SSH-side passive enumeration, because absence of evidence is not evidence of absence — and historical TMM crash patterns suggest that fragile in-line devices do exist** (sources: F5 K39580786 at https://my.f5.com/manage/s/article/K39580786; F5 K10251520 at https://my.f5.com/manage/s/article/K10251520).

## Hand off to /slo-architect

`tla_required` should remain `false` for the v1 wedge — there is no concurrent state machine, no distributed consensus, no resource-ownership invariant; the only state is "TCP connection per probe, one logical scan per (target, port, group)". The architectural decisions for `/slo-architect` are: module/library naming under Nettacker convention; algorithm-name table format and refresh policy; verdict response shape; CLI/Web-UI surface (e.g. is this a `pqc_scan` module name, or `tls_pqc_scan` + `ssh_pqc_scan` as a pair?); and how the `--no-pqc-probe` safety opt-out integrates with Nettacker's existing module-argument system.
