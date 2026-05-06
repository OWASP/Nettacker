# Threat model — pqc-compliance-scanner

Scope: the new `pqc_scan` module + `PqcLibrary` / `PqcEngine`. Components that already exist in Nettacker (CLI, module loader, SQLite store) are out-of-scope here — they are covered by Nettacker's existing security posture.

## Components in scope

| ID | Component | Type | Trust |
|---|---|---|---|
| C1 | `pqc_scan.yaml` | Module manifest (data) | Trusted (in repo, code review gate) |
| C2 | `PqcLibrary.tls_pqc_scan()` | Active TLS prober (raw TCP + ClientHello bytes) | Operator-trusted, network-untrusted on response |
| C3 | `PqcLibrary.ssh_pqc_scan()` | Passive SSH KEXINIT reader (raw TCP) | Operator-trusted, network-untrusted on response |
| C4 | `TLS_PQC_NAMED_GROUPS` / `SSH_PQC_KEX_ALGORITHMS` | Static algorithm tables (data) | Trusted |
| C5 | `PqcEngine.apply_extra_data()` | Verdict computation | Trusted |

## STRIDE per component

Class-elimination framing: each cell states *what makes the entire class go away*, not "fix this bug instance".

### C1 — `pqc_scan.yaml`

| Threat | Disposition |
|---|---|
| **Spoofing** | N/A — manifest is loaded from disk by Nettacker's TemplateLoader, no network input path. |
| **Tampering** | Eliminated by — repo code-review + signed-commit policy (`.pre-commit-config.yaml`) protects manifest integrity at rest. |
| **Repudiation** | N/A — no actor-attribution requirement on a static manifest. |
| **Information disclosure** | N/A — manifest contains only the algorithm-name list, all of which are public IETF / OpenSSH identifiers. |
| **Denial of service** | Mitigated by — port lists are bounded constants (≤ 13 TLS ports, 2 SSH ports); operator's `--excluded-ports` further reduces. |
| **Elevation of privilege** | N/A — manifest is data, not code. |

### C2 — `PqcLibrary.tls_pqc_scan()` (active TLS prober)

| Threat | Disposition |
|---|---|
| **Spoofing** | N/A — we don't authenticate to the target; this is observation. |
| **Tampering** | Eliminated by — single-record read after ClientHello; we never act on, store, or forward the response payload beyond extracting the named-group codepoint and alert level. |
| **Repudiation** | Mitigated by — every probe is logged via `BaseEngine.process_conditions()` to the existing SQLite store with `(date, target, port, scan_id)`. |
| **Information disclosure** | Eliminated by — we transmit no credentials, session keys, or operator data. ClientHello SNI carries the operator-supplied target hostname only. |
| **Denial of service** *(target — the most material risk per founder confirmation)* | Mitigated by — (a) one TCP connection per probed group (≤ 8 groups in v1); (b) framework-level `time_sleep_between_requests` + `thread_per_host` rate-limit; (c) `pqc_no_active_probe=true` opt-out for known-fragile environments; (d) ClientHello shape is strictly RFC 8446-conformant per [security.md §1](pqc-compliance-scanner-security.md). Residual: a sufficiently fragile in-line device may still react badly to a ClientHello with an unrecognized supported_groups codepoint — this is an inherent risk of *any* PQC-aware scanner and is the reason the opt-out exists. |
| **Denial of service** *(scanner)* | Mitigated by — `timeout` parameter (default 5s) bounds per-probe wait; library catches `socket.timeout` / `ConnectionError` and records as `unknown` rather than retrying. |
| **Elevation of privilege** | N/A — process runs at operator's existing privilege; module spawns no subprocesses, opens no files, performs no `setuid` / `setgid`. |

### C3 — `PqcLibrary.ssh_pqc_scan()` (passive SSH KEXINIT reader)

| Threat | Disposition |
|---|---|
| **Spoofing** | N/A. |
| **Tampering** | Eliminated by — same single-packet read as C2. |
| **Repudiation** | Mitigated by — same logging path as C2. |
| **Information disclosure** | Eliminated by — we send only the SSH-2.0 client banner string; no credentials. |
| **Denial of service** *(target)* | Eliminated by — exactly one TCP connection per (host, port). Reading SSH KEXINIT is functionally identical to what a vanilla SSH client does on every connect; production SSH servers handle this constantly. |
| **Denial of service** *(scanner)* | Mitigated by — bounded read (KEXINIT packet length is capped by SSH protocol per RFC 4253 §6 at 35,000 bytes); `timeout` parameter bounds wait. |
| **Elevation of privilege** | N/A. |

### C4 — Algorithm tables

| Threat | Disposition |
|---|---|
| **Spoofing** | N/A. |
| **Tampering** | Eliminated by — repo code-review; tables ship as Python module-level constants, not runtime config. |
| **Repudiation** | N/A. |
| **Information disclosure** | N/A — public values. |
| **Denial of service** | Mitigated by — table size is bounded by code review (≤ 8 TLS codepoints, ≤ 4 SSH algorithms in v1). |
| **Elevation of privilege** | N/A. |

### C5 — `PqcEngine.apply_extra_data()` (verdict computation)

| Threat | Disposition |
|---|---|
| **Spoofing** | N/A. |
| **Tampering** | Mitigated by — verdict computation is pure-function over response dict; no side effects, no state mutation outside the dict. |
| **Repudiation** | N/A. |
| **Information disclosure** | N/A. |
| **Denial of service** | Eliminated by — O(n) over a bounded list. |
| **Elevation of privilege** | N/A. |

## Abuse cases (3 per new surface)

### Surface — TLS active probe (`tls_pqc_scan`)

- **tm-pqc-compliance-scanner-abuse-1** — *Operator scans a known-fragile in-line device.* Attacker: the operator (unintentional). Step: includes a target IP that is a legacy F5 LTM with a TLS firmware bug; the BIG-IP TMM crashes when receiving an unknown supported_groups codepoint. Outcome: prod outage, operator blamed. Control: `pqc_no_active_probe=true` opt-out documented in user-facing module help text; default port list does NOT include common load-balancer health-check ports (e.g. 8080 — this is in default list per ssl_expiring_certificate.yaml; we INHERIT this from Nettacker's existing pattern, not introduce). Operator can `--excluded-ports 8080`.
- **tm-pqc-compliance-scanner-abuse-2** — *Adversary publishes a poisoned ServerHello.* Attacker: a malicious target server (e.g., honeypot the operator scanned by mistake). Step: server responds with a maximally-large ServerHello (or fragmented record sequence) attempting to exhaust scanner memory or trigger a parser bug. Outcome: scanner OOM or crash. Control: `recv()` is bounded to `MAX_RECORD_SIZE` (16,384 bytes per RFC 8446 §5.1 — we read at most one record); single-record-read invariant per [security.md §3](pqc-compliance-scanner-security.md). Residual: a parser bug in our code remains possible — mitigated by golden-byte fixtures + fuzz tests in v2.
- **tm-pqc-compliance-scanner-abuse-3** — *Repeated scans probe a single target into oblivion.* Attacker: a misconfigured CI cron job. Step: scheduled scan repeats every minute against the same target; `thread_per_host` is set high; target sees N×8 connections/min per scan. Outcome: target rate-limit triggers, blocks the scanner IP. Control: framework-level `time_sleep_between_requests` and `thread_per_host` (existing); module documentation explicitly recommends conservative values for PQC scanning.

### Surface — SSH passive probe (`ssh_pqc_scan`)

- **tm-pqc-compliance-scanner-abuse-4** — *Server sends an oversized banner / KEXINIT.* Attacker: malicious target. Step: server sends a 100MB banner string before the SSH-2.0 line. Outcome: scanner buffers indefinitely. Control: banner read capped at 255 bytes per RFC 4253 §4.2; KEXINIT packet read capped at 35,000 bytes per RFC 4253 §6; `timeout` enforced.
- **tm-pqc-compliance-scanner-abuse-5** — *Server alert/honeypot logs the scanner's banner.* Attacker: a defender's honeypot logging the scanner. Step: scanner sends `SSH-2.0-Nettacker-PQC-Scan` banner; honeypot captures it. Outcome: information leak about the scan tool. Control: client banner uses generic string `SSH-2.0-OpenSSH_for_Windows_8.1` (mimics common client) OR `SSH-2.0-Nettacker` (transparent). Decision: use **transparent** banner — Nettacker is a pen-test tool with explicit consent assumed; obfuscation would be misleading. Documented in the library code.
- **tm-pqc-compliance-scanner-abuse-6** — *Connection-resource exhaustion against the scanner.* Attacker: malicious target. Step: target accepts TCP but never sends a banner. Outcome: scanner thread blocks for `timeout` seconds, holding a file descriptor. Control: `timeout` default 5s; thread is reaped by Nettacker's existing thread-pool watchdog; one fd per probe.

## Compliance mapping

| Framework | Relevant control(s) | How this module addresses it |
|---|---|---|
| **SOC 2** | CC6.1 (logical access — encryption in transit) | Module helps the customer *audit* their TLS/SSH posture against the SOC 2 cryptography control; this module itself performs no encryption. |
| **OWASP ASVS v4** | V6 (Stored Cryptography), V9 (Communications) | V9.1.2 ("verify TLS configuration") is the buyer-side control this module supports. The module is itself an audit tool, not a system that needs to be ASVS-audited. |
| **NIST SP 800-53 rev5** | SC-8 (Transmission Confidentiality), SC-12 (Cryptographic Key Establishment), SC-13 (Cryptographic Protection) | The output verdict directly answers the SC-13 control assessor's question "does this system use FIPS-validated PQC primitives". |
| **OMB M-23-02 / NSM-10** | Annual cryptographic-system inventory | Output JSON can be ingested directly into the inventory submission template. |
| **CNSA 2.0** | Approved-algorithm gating (ML-KEM-1024 / ML-DSA-87 / AES-256 / SHA-384) | Verdict explicitly flags whether ML-KEM-1024 (CNSA 2.0 mandatory) is in the advertised set. |

## Out of scope

- AI / ML-specific threats (no AI component — `ai_component: false`).
- GDPR / personal data (the module processes only network-reachability data and operator-supplied target identifiers — no personal-data class).
- Cryptographic-library threats (we use no crypto library beyond stdlib observation).
