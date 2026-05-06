# Feature security defaults — pqc-compliance-scanner

Scope: this document is the **feature-scoped** security overlay for the `pqc_scan` module. The repo-root [SECURITY.md](../../../SECURITY.md) (OWASP Nettacker's vulnerability-disclosure policy) is intentionally untouched.

## Top risks (verbatim from idea doc)

The following block is fenced so any markdown / HTML / YAML metacharacters from the source idea doc are treated as literal text, not interpretable content.

~~~text
- Breach (availability subclass): A malformed or unusually-shaped TLS 1.3 ClientHello (e.g., key_share with an unrecognized PQC group) crashes a fragile in-line device — old F5 LTM with stale TLS firmware, a legacy SSL-terminating load balancer, or a brittle WAF. Adversary is the operator scanning their own fleet. Data does not leave the trust boundary, but the LB falls over and the ops team blames the scanner.

- Compliance fine: Mis-reporting "PQC ready" on a federal-contractor attestation against NSM-10 / OMB M-23-02 timelines, or on a DORA Article 28 ICT third-party register. Specific failure: scanner reports `pqc_ready` because the server advertised an ML-KEM group, but the server's certificate chain still uses classical RSA/ECDSA signatures, which fails the "end-to-end PQ" criterion auditors actually want.

- Prolonged outage: A scheduled Nettacker run in CI fans out to thousands of endpoints; an aggressive default of "probe all 12 PQC named groups individually" produces 12× the connections per target. A frontend load balancer's connection-rate alarm pages oncall at 02:00.
~~~

## Mandatory invariants the implementation must hold

1. **TLS ClientHello shape is strictly RFC 8446-conformant.** No unknown extensions in unknown positions. No length manipulation. No deliberately fragmented records. Validation: golden-byte fixture tests in `tests/core/lib/test_pqc.py` compare emitted ClientHello bytes against a hand-checked reference encoding for at least three PQC named groups. Any change to ClientHello generation requires updating the fixtures and a documented review.

2. **One TCP connection per (target_host, target_port, named_group) probe.** No connection re-use, no parallel pipelining inside the library. The framework's existing `time_sleep_between_requests` and `thread_per_host` controls are the ONLY rate-limiters; the library does not bypass them.

3. **No handshake completion.** The library MUST close the TCP socket after reading at most one TLS record (or one SSH KEXINIT packet). Validation: code review checks that `socket.close()` follows `socket.recv()` in every code path, and there is no `socket.send()` after `recv()` in the probe paths.

4. **Honor the `pqc_no_active_probe` opt-out.** When set via `--modules-extra-args pqc_no_active_probe=true`, the TLS active-probe path is bypassed — only the SSH passive-KEXINIT path runs. This is the operator's escape hatch when a known-fragile network device is in scope.

5. **Probed-group set is bounded and documented.** The `TLS_PQC_NAMED_GROUPS` table contains ≤ 8 codepoints in v1. Adding more requires updating this document and the table comment with the rationale.

6. **Verdict honesty.** `pqc_ready` is set only when at least one *standardized* group/KEX is advertised (`status: standardized` in the table). Drafts and experimentals contribute to advertised-list output but never trigger `pqc_ready`. The `compliance_notes` field MUST always state which standard the verdict maps to.

7. **No new outbound surfaces.** The module makes ONLY the documented probe connections. No DNS queries beyond the existing OS resolver call. No telemetry. No third-party API calls. No file writes outside Nettacker's existing log/DB paths.

## Inherited from Nettacker

- Operator authorization to scan: governed by Nettacker's existing disclaimer (README) and SECURITY.md disclosure policy.
- Result persistence: SQLite at `.nettacker/data/nettacker.db` (existing); no new sensitive-key class.
- API key handling: inherited from `nettacker.config` (the module never touches API keys).
- Sensitive-header redaction: handled by `remove_sensitive_header_keys()` in [nettacker/core/utils/common.py](../../../nettacker/core/utils/common.py) before DB write — the module emits no HTTP headers, so this is automatic.

## Out of scope for this module's security review

- TLS handshake completion safety (we don't complete handshakes).
- Cryptographic key handling (we generate no keys).
- Authentication and authorization to Nettacker itself (existing concern).
- Privacy of the target host's identity (operator-supplied).

## Cross-references

- Threat model: [pqc-compliance-scanner-threat-model.md](pqc-compliance-scanner-threat-model.md) (STRIDE per component, abuse cases, compliance mapping).
- Stack decision rationale for "no new deps": [pqc-compliance-scanner-stack-decision.md](pqc-compliance-scanner-stack-decision.md).
- Source-of-truth for safety constraints: synthesis line *"The design must (a) send only RFC-compliant ClientHello shapes, (b) cap connections-per-target-per-run at one per probed group, (c) provide a `--no-pqc-probe` opt-out"*: [synthesis.md](../research/pqc-compliance-scanner/synthesis.md).
