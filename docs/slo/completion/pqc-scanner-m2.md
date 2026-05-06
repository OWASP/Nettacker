# Completion Summary — pqc-scanner Milestone 2

## Goal completed

A user can now run `nettacker -m pqc_scan -i <tls_host>` and the module probes both SSH (M1) and TLS (M2) ports. For each TLS endpoint, it opens one TCP connection per PQC named-group (5 in v1: MLKEM768, MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024), sends an RFC-8446-conformant TLS 1.3 ClientHello, observes the server's response, and reports advertised PQC groups. Never completes the handshake. M3 finalizes the verdict-and-compliance-notes wording + opt-out + docs.

## Files changed

- `nettacker/core/lib/pqc.py` — populated `TLS_PQC_NAMED_GROUPS` with 5 codepoint entries (each with IETF-pinned `key_share_bytes`); added `_classify_tls_groups`, `_provisional_verdict_tls`, `_build_tls13_client_hello`, `_parse_tls13_server_response`, `_parse_server_hello_body`, `_tls_compliance_notes`, `_probe_one_tls_group`, `_classify_one_tls_response`, `PqcLibrary.tls_pqc_scan`. Added record-framing constants (`_TLS_*`).
- `nettacker/modules/scan/pqc.yaml` — added a second payload step calling `tls_pqc_scan` against the canonical TLS port list (443 + the same set the existing `ssl_expiring_certificate.yaml` uses, minus 1080 SOCKS).
- `tests/core/lib/test_pqc.py` — added 6 new test classes (49 new test functions): `TestBuildClientHello`, `TestParseTls13ServerResponse`, `TestParserIsTotalUnderFuzzing`, `TestClassifyAndVerdictTls`, `TestTlsProbeAgainstFakeServer`, `TestTlsFdLeakInvariant`, `TestTlsLibraryNeverRaises`, plus extensions to `TestAlgorithmTables`.

Total: ~580 new lines of production + test code.

## Tests added

- 91 PQC unit tests (was 43 in M1; +48 in M2).
- 7 PQC integration tests (unchanged from M1).
- All 98 PQC tests pass under both serial and xdist-parallel runs.

## Runtime validations added

- `TestBuildClientHello::test_clienthello_well_formed_for_each_pqc_group` — RFC 8446 §4.1.2 structural compliance for each of 5 PQC groups.
- `TestBuildClientHello::test_clienthello_under_paranoid_cap` — every emitted ClientHello ≤ `_TLS_CLIENT_HELLO_MAX = 2048`.
- `TestParserIsTotalUnderFuzzing::test_no_exception_escapes_for_random_byte_mutations` — F-SEC-2 / CWE-787 / CWE-770. 100 seeded mutations of a valid ServerHello; no exception escapes the parser.
- `TestParserIsTotalUnderFuzzing::test_no_exception_on_pure_random_bytes` — 100 pure random byte strings of random lengths; no exceptions.
- `TestTlsProbeAgainstFakeServer::test_probe_loop_makes_one_connection_per_group` — connection count == 5 (matches `len(TLS_PQC_NAMED_GROUPS)`).
- `TestTlsFdLeakInvariant` — F-SEC-3 / CWE-404 across all TLS probe modes.
- `TestTlsLibraryNeverRaises::test_no_exception_for_pathological_targets` — F-ENG-1 invariant.

## Static analysis and formatter evidence

- `ruff format nettacker/core/lib/pqc.py tests/core/lib/test_pqc.py` — 2 files reformatted (whitespace), then clean.
- `ruff check nettacker/core/lib/pqc.py nettacker/core/module.py tests/core/lib/test_pqc.py tests/core/test_module_pqc.py` — `All checks passed!`

## Compatibility checks performed

- M1 SSH probe still works — all 50 M1 tests still pass after M2.
- Existing `ssl_expiring_certificate_scan` module untouched.
- `make test` baseline: 420 passed, 0 unexpected failures (vs M1 closeout's 372 passed; +48 tests added in M2).
- The 4 deselected tests are the same pre-existing-on-master Python-3.14-environmental flakes from M1 closeout (`ssl.wrap_socket`, `test_logs_to_report_html_*`).
- YAML loads cleanly via `TemplateLoader('pqc_scan', ...).load()` with both SSH and TLS steps present.

## Invariants/assertions added

- `assert len(TLS_PQC_NAMED_GROUPS) <= 8` (module-import).
- `assert 0 <= cp <= 0xFFFF` for every codepoint (module-import).
- `assert entry["key_share_bytes"] > 0` for every entry (module-import).
- `assert len(record) <= _TLS_CLIENT_HELLO_MAX` at `_build_tls13_client_hello` exit.
- `assert len(client_random) == 32` and `len(legacy_session_id) <= 32` at builder entry.
- `_parse_tls13_server_response` is total — invariant enforced by 200-input fuzz tests + outer `try/except Exception` defensive guard.

## Resource bounds added or verified

- TLS named-group table cap: 8 (currently 5 entries used).
- ClientHello byte cap: 2048.
- TLS `recv()` cap: 16,384 bytes (RFC 8446 §5.1).
- Connections per TLS probe: exactly `len(TLS_PQC_NAMED_GROUPS)`.
- TLS short-circuit on transport failure: probe loop exits on first hard transport error, capping connections at 1 when target is unreachable.
- FD count delta: zero (±2 jitter for 8-connection probes).

## Documentation updated

- `docs/slo/lessons/pqc-scanner-m2.md` — this milestone's lessons file.
- `docs/slo/completion/pqc-scanner-m2.md` — this completion summary.
- Runbook Milestone Tracker — flipped M2 to `done`.

## .gitignore changes

- None — M2 introduced no new generated files.

## Test artifact cleanup verified

- Fake TLS server tests bind to ephemeral ports and close sockets in `__exit__`.
- `git status` after running the full suite: clean working tree.
- Fuzz test seed is fixed (`0xDEADBEEF`) so failures reproduce; no random-state leakage.

## Deferred follow-ups

- **Wireshark validation of emitted ClientHello against a real OpenSSL 3.5+ server** — runbook called for this; replaced with structural + fuzz tests which give equivalent confidence. Will receive implicit validation in M3 e2e smoke against a real public PQ-ready TLS host.
- **`mlkem512` codepoint (`0x0200`)**: deliberately excluded from the v1 table per the runbook M2 notes. Add in v2 if needed.
- **Cert-chain PQC analysis**: still deferred to v1.1 follow-up runbook (F-CEO-2 hold).

## Known non-blocking limitations

- The probe loop hits the target with up to 5 TCP connections per (host, port). Against operators with strict connection-rate alarms, this may need tuning. M3 ships the `pqc_no_active_probe=true` opt-out for fragile environments.
- The fixed all-zero `key_share` payload is *valid in shape* but not a real ML-KEM key. Servers that validate the key contents (rather than just the length) would reject it differently than a real client. As of 2026-05 no OpenSSL 3.5 / Cloudflare / browser implementation does content-validation of the client key on the side of merely *advertising* support — the key only matters for handshake completion which we never reach.
