---
name: pqc-compliance-scanner
created: 2026-05-06
status: ideation
tla_required: false    # provisional — /slo-architect finalizes this
---

# PQC compliance scanner for OWASP Nettacker

## The pain
A security engineer at a US federal contractor (operating under NSM-10 / NIST SP 1800-38C transition guidance) is asked by an auditor in early Q2-2026: "what percentage of your externally exposed TLS endpoints negotiate post-quantum key exchange today, and which of your SSH bastions advertise hybrid PQ kex?" She has 800-ish endpoints across colos and clouds. Her last bad day was last Friday: she wrote a bash loop around `openssl s_client -groups X25519MLKEM768` against a sample of 30 hosts she'd already manually deployed `oqsprovider` against. The remaining 770 are unknowns. She files the audit answer as "in progress" and books the same problem on next quarter's plate.

## Five capabilities the user described without realizing
- Enumerate which PQC named groups a TLS 1.3 endpoint will accept, without needing the scanner host to have liboqs/oqsprovider installed.
- Enumerate which PQC KEX algorithms an SSH server advertises, by reading SSH KEXINIT, without completing the handshake.
- Emit a per-target verdict (`pqc_ready` / `hybrid_only` / `classical_only` / `unknown`) so a CI gate can pass/fail.
- Diff posture across scan runs (Nettacker already does drift detection — this just adds a posture dimension), so quarterly migration progress is automatic.
- Run safely against fragile production endpoints — no malformed handshakes, no flooding, predictable connection budget per target.

## Top risks
- **Breach (availability subclass)**: A malformed or unusually-shaped TLS 1.3 ClientHello (e.g., key_share with an unrecognized PQC group) crashes a fragile in-line device — old F5 LTM with stale TLS firmware, a legacy SSL-terminating load balancer, or a brittle WAF. Adversary is the operator scanning their own fleet. Data does not leave the trust boundary, but the LB falls over and the ops team blames the scanner. Mitigation discipline: stay inside RFC 8446 / RFC-draft-aligned ClientHello shapes, send one connection per probe, never fragment, never flood.
- **Compliance fine**: Mis-reporting "PQC ready" on a federal-contractor attestation against NSM-10 / OMB M-23-02 timelines, or on a DORA Article 28 ICT third-party register. Specific failure: scanner reports `pqc_ready` because the server *advertised* an ML-KEM group, but the server's certificate chain still uses classical RSA/ECDSA signatures, which fails the "end-to-end PQ" criterion auditors actually want. Scale: contract loss for federal contractors; up to 1% of annual turnover under DORA enforcement (effective Jan 2025).
- **Prolonged outage**: A scheduled Nettacker run in CI fans out to thousands of endpoints; an aggressive default of "probe all 12 PQC named groups individually" produces 12× the connections per target. A frontend load balancer's connection-rate alarm pages oncall at 02:00. Oncall identifies Nettacker as the source within ~20 minutes and disables the entire `ssl_*` module family for the quarter — losing not only PQC posture but expiring-certificate scans too. Defection looks like the team writing their own bespoke tool because Nettacker's module felt unsafe.

## Approach A — conservative (passive enumeration)
- **Effort**: 1 person-week.
- **Wedge**: Ship two things in week 1:
  1. **SSH posture probe** — open TCP, send SSH-2.0 client banner, parse SSH KEXINIT, extract the server's `kex_algorithms` / `host_key_algorithms` / `encryption_algorithms_*` lists, flag any that match a curated PQC allowlist (`sntrup761x25519-sha512@openssh.com`, `mlkem768x25519-sha256`, `mlkem768nistp256-sha256`, etc.). No handshake completion.
  2. **TLS 1.3 PQC named-group probe** — for each PQC group in our allowlist (`X25519MLKEM768=0x11ec`, `SecP256r1MLKEM768=0x11eb`, `mlkem512=0x0200`, `mlkem768=0x0201`, `mlkem1024=0x0202`, plus draft-ietf X-Wing once codepoint stable), send a single well-formed TLS 1.3 ClientHello with `supported_groups` + `key_share` for that group. Observe the ServerHello / HelloRetryRequest / handshake_failure alert. We never complete the handshake; we never need a PQC implementation on the scanner host.
- **Risks**: TLS 1.3 ClientHello byte construction is fiddly (extensions length, key_share group lengths). Some servers silently drop instead of alerting — we treat silence after a timeout as "not supported" but log the ambiguity. Probing 6+ named groups individually means 6+ connections per target; we cap at one logical scan per target per run and stagger via Nettacker's existing thread limits.

## Approach B — cloud / SaaS (oqsprovider-backed)
- **Effort**: 3–4 person-weeks.
- **Wedge**: Ship a Docker variant of Nettacker that bundles OpenSSL 3.x + Open Quantum Safe `liboqs` + `oqsprovider`. Shell out to `openssl s_client -groups` for actual handshake completion against each PQC group. Provides true end-to-end "this works" evidence, not just "the server advertises support."
- **Risks**: Heavy build pipeline (compile liboqs from source per platform). ABI churn — oqsprovider is pre-1.0. Locks users to the Docker image, breaks the existing pip/poetry install path. Significant supply-chain surface (liboqs vendored crypto). Worse, completing real PQ handshakes against production endpoints is a *more* invasive scan than Approach A.

## Approach C — local / desktop (custom Python TLS / SSH stack)
- **Effort**: 2–3 person-weeks.
- **Wedge**: Use `tlsfuzzer` or a custom TLS 1.3 client (e.g., port a minimal TLS 1.3 record/handshake layer, or use `python-cryptography` primitives) to natively speak PQ named groups in Python without external system deps. For SSH, extend paramiko with PQ-aware KEX advertisement.
- **Risks**: Python ecosystem PQ coverage is thin — `python-cryptography` does not yet expose ML-KEM. `tlsfuzzer` is test-fixture quality, not production-scanner quality. Maintaining a custom TLS 1.3 handshake module in a security tool is an ongoing audit burden — a parser bug becomes a CVE in Nettacker itself.

## Recommendation
**Approach A**. The wedge ships in one week, has the smallest blast radius (no handshake completion, no new system deps, no malformed bytes on the wire), and reuses Nettacker's existing module/library convention exactly. The honest limitation — "we report what the server *advertises*, not what it can actually *complete*" — is documented in the verdict (`advertised_pqc` vs `negotiated_pqc`) and is enough for the inventory question auditors are actually asking in 2026. Approach B is the natural v2 (gated behind a Docker-only flag) once the inventory wedge has users; Approach C is rejected as a maintenance trap.

## Confirmations from founder (2026-05-06)
- Target user is the security engineer doing endpoint inventory. Nettacker is the right home (vs. a standalone tool) precisely because the same engineer can already see other scans in one place — PQC posture becomes one more lens on an asset they're already scanning.
- Single-asset input contract: user gives a URL, IP, or `host:port`. If port omitted, default to the same port lists Nettacker's existing TLS/SSH scans use (e.g., `ssl_expiring_certificate.yaml` defaults: 21/25/110/143/443/587/990/1080/8080; SSH default: 22). Bulk scanning is Nettacker's job at the framework level — the module stays per-asset.
- "Worst day" is reaffirmed as **crashing the target** (availability). Light and reliable is the dominant constraint, not feature breadth. This locks in: single connection per probe, RFC-compliant ClientHello shapes only, configurable per-target rate cap, and the `--no-pqc-probe` opt-out called out in `synthesis.md`.

## Open questions for /slo-research
1. Authoritative current list of TLS 1.3 named-group codepoints for PQC: ML-KEM standalone (RFC pending), hybrid X25519MLKEM768 / SecP256r1MLKEM768 (draft-ietf-tls-ecdhe-mlkem), X-Wing — confirm IANA TLS Named Group registry assignments as of 2026-Q2.
2. Authoritative current list of OpenSSH PQC KEX algorithm strings — `sntrup761x25519-sha512@openssh.com`, `mlkem768x25519-sha256` (OpenSSH 9.9+), and any others added in OpenSSH 10.x.
3. NIST PQC standardization status as of 2026-05: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) — confirm what counts as "compliant" vs "compliant-pending" for a scanner verdict.
4. Compliance frameworks the verdict should map to: NIST SP 1800-38C, OMB M-23-02 timelines, NSM-10, ENISA "Post-Quantum Cryptography: Current state and quantum mitigation" (2024 update), CNSA 2.0.
5. Prior-art tools: testssl.sh PQC support status, Qualys SSL Labs API, sslyze, scanigma — what do they already report so we don't ship a worse copy.
6. Safety norms: are there documented cases of malformed TLS ClientHellos crashing production load balancers (F5, Citrix Netscaler, AWS ALB)? Establishes the "what shapes are safe" rule we encode.
7. Do existing Nettacker module YAMLs have a precedent for emitting a multi-valued "verdict" enum field, or is the current convention only boolean conditions? (Affects how we model `pqc_ready` / `hybrid` / `classical_only` in the response shape.)
