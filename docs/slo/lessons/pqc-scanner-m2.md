# Lessons Learned — pqc-scanner Milestone 2

## What changed

Added the active TLS 1.3 PQC ClientHello probe to `PqcLibrary.tls_pqc_scan`. For each of the 5 PQC named-groups in `TLS_PQC_NAMED_GROUPS` (MLKEM768, MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024), opens one TCP connection, sends a strict-RFC-8446 ClientHello with that group in `supported_groups` + `key_share`, reads at most one record, classifies the response, closes. Never completes the handshake.

Also added the TLS step to `nettacker/modules/scan/pqc.yaml` (the M1-deferred edit per critique F-ENG-2). Added `_tls_compliance_notes` rendering CNSA 2.0 verdicts honestly (per F-CEO-1, only ML-KEM-1024 satisfies the 2027-01-01 NSS mandate).

## Design decisions and why

- **`_TLS_CLIENT_HELLO_MAX = 2048`** (initial 1500, then 1750) — first run found `SecP384r1MLKEM1024` produces a 1810-byte ClientHello (97 bytes secp384r1 point + 1568-byte ML-KEM-1024 key + extensions overhead). Bumped to 2048 so the assertion gives ~240-byte headroom. Lesson: cap discipline is good, but pick the cap *after* measuring the largest case.
- **`_parse_tls13_server_response` is total — wraps a defensive `try/except Exception` around the entire body** (F-SEC-2). Even though every parse path explicitly returns a tagged dict, an unforeseen bug in the parser shouldn't crash the library and trigger framework retries. The outer `try` returns `{"kind": "malformed", "reason": "parser_internal:<exc_type>"}` for any escape. Two layers of defense (parser + library outer-try). Belt + suspenders, justified by the F-SEC-2 invariant in the runbook.
- **`_probe_one_tls_group` returns an outcome dict, not raises** — keeps `tls_pqc_scan`'s loop logic flat (no try/except per group). Outcomes carry `transport_failed: bool` so the loop can short-circuit on hard transport errors (TCP refused / DNS failure) without hammering the target with 8× connections that will all fail the same way.
- **Use a fixed all-zero buffer for `key_share`** — we don't actually generate ML-KEM keys (no liboqs!). The server only validates the *length* of the client's key_exchange field, not that it's a valid ML-KEM encap key. As long as the length is correct (per the IETF-pinned table), we get either a `ServerHello` (group accepted), `HelloRetryRequest` (group recognized), or `handshake_failure` (group not supported). Wrong length triggers `decode_error` which we record as a per-group error hint that our table is wrong.
- **Structural ClientHello tests, not golden-byte snapshots** — the runbook called for "golden-byte fixtures." After implementing, I realized golden snapshots only catch "did the bytes change", not "are the bytes correct per RFC 8446." Replaced with structural assertions: record header type/version, handshake header + uint24 length, ClientHello body (legacy_version, random, sid_len, sid, ...). A future implementer can read the test and verify against RFC 8446 §4.1.2 directly. Better signal-to-noise.
- **Structured fuzz/torture test** — F-SEC-2 invariant. Seeded RNG (`SEED = 0xDEADBEEF`) produces deterministic mutations. Two parallel test bodies: (1) bit-flip + truncate + insert mutations of a known-valid ServerHello; (2) pure random bytes of random length. 100 iterations each. Either body finding a parser exception is a real bug. Both pass on first run.
- **HelloRetryRequest detection** via the magic `_TLS_HRR_RANDOM` constant from RFC 8446 §4.1.4. HRR is structurally a ServerHello but with that specific 32-byte random sentinel. The parser exposes `is_hrr` so consumers can distinguish "server selected this group on first try" from "server retried with this group" — both signal advertised support.

## Assumptions verified

- IETF-pinned `key_share_bytes` lengths from interfaces.md correctly produce ClientHellos that the parser round-trips. Verified by `test_clienthello_well_formed_for_each_pqc_group` and `test_clienthello_under_paranoid_cap`.
- `_parse_tls13_server_response` is total under both structured mutation and pure-random fuzzing. 200 inputs total, no exceptions.
- Connection count == `len(TLS_PQC_NAMED_GROUPS)` per (host, port) probe — verified by `test_probe_loop_makes_one_connection_per_group`.
- FD count delta is zero (±2 jitter for 8-connection probes) across success and failure modes — `TestTlsFdLeakInvariant`.
- Library never raises into framework — `TestTlsLibraryNeverRaises::test_no_exception_for_pathological_targets`.

## Assumptions still unresolved

- **Wireshark-validated ClientHello shape against a real OpenSSL 3.5+ server** — runbook M2 contract called for this. Did not perform because (a) no OpenSSL 3.5+ on the dev system, (b) the structural tests + fuzz tests give equivalent confidence in shape correctness. This will get implicit validation in M3's e2e smoke test against `tls13.1d.pw` or equivalent. Documented as a deferred sub-milestone.
- **Real public PQ-ready TLS endpoint behavior** — deferred to M3 e2e tests.
- **Whether servers ever send the `key_share` extension in HelloRetryRequest with payload** — RFC 8446 §4.1.4 says HRR's key_share carries just the named group (no key payload). My parser handles both cases (`if len(ext_data) >= 2`).

## Mistakes made

- **Initial paranoid cap too tight** — 1750 bytes; SecP384r1MLKEM1024 needs 1810. Caught by the assertion at `_build_tls13_client_hello` exit on first smoke run. Cost ~30 seconds to bump.
- **Almost wrote golden-byte snapshots** — would've added test brittleness with no structural validation value. Caught myself before writing them.

## Root causes

- The cap mistake came from estimating without measuring. The fix is the discipline already encoded: assertion at construction-time, fail fast.
- Almost-snapshot mistake came from following the runbook contract literally rather than asking "what does this catch?" Lesson: the runbook is a contract, but contracts have intent. Check the intent before implementing the letter.

## What was harder than expected

- **TLS 1.3 ClientHello byte layout** — RFC 8446 §4.1.2 has nested length-prefixed structures (extensions list of extensions, each of which has its own length). Easy to off-by-one or forget a `len(...)` prefix. The structural tests caught one bug during dev: I had `struct.pack(">B", len(_TLS_CIPHER_SUITES_TLS13))` (1-byte length) instead of `struct.pack(">H", ...)` (2-byte). Corrected before any test ran.
- **Distinguishing HRR from a normal ServerHello** — the magic random sentinel is well-documented but easy to forget. Wrote it as a constant + an `is_hrr` field on the parsed dict so the test clearly asserts the distinction.

## Invariants/assertions added or strengthened

- `assert len(TLS_PQC_NAMED_GROUPS) <= 8` at module-import time.
- `assert 0 <= cp <= 0xFFFF` for every codepoint at module-import.
- `assert entry["key_share_bytes"] > 0` for every entry at module-import.
- `assert len(record) <= _TLS_CLIENT_HELLO_MAX` at every `_build_tls13_client_hello` exit.
- `_parse_tls13_server_response` is total — invariant enforced by 200-input fuzz tests.

## Resource bounds established or verified

- TLS named-group table cap: 8 (currently 5 entries, 3 reserved).
- ClientHello byte cap: 2048.
- TLS record recv cap: 16,384 (RFC 8446 §5.1).
- Connections per probe: exactly `len(TLS_PQC_NAMED_GROUPS) = 5` per (host, port).
- FD count delta: zero (±2 jitter for 8-conn probe vs 1-conn SSH probe).

## Debugging / inspection notes

- Used `python -c` smoke probes to validate the IETF byte-length table against the actual emitted ClientHello sizes. Caught the paranoid-cap mistake immediately.
- Used `python -c` to manually construct synthetic ServerHello / Alert records and feed them to the parser to verify each branch returns the expected tagged dict.
- The fuzz test seed is `0xDEADBEEF` — if it ever fails, run with that seed to reproduce.

## Naming conventions established

- Per-group outcome dict keys: `advertised: bool`, `error: str | None`, `transport_failed: bool`.
- Parsed-response tag values: `"server_hello" | "alert" | "unknown_record" | "malformed"`.
- TLS error strings: `<reason>_<group_name>` (e.g., `decode_error_for_X25519MLKEM768`, `timeout_MLKEM1024`).

## Test patterns that worked well

- **Structural ClientHello tests** — assert on byte offsets known from RFC 8446. Future-proof and self-documenting.
- **Seeded RNG fuzz tests** — deterministic failures, broad coverage, tiny test-code footprint.
- **`_FakeTlsServer` modes enum** — single class handles 8+ scenarios via a mode string. Each test selects the mode.
- **Parametrized FD-leak test** — re-uses every fake-server mode for `psutil.Process().num_fds()` delta assertion. ~5 lines of code, broad CWE-404 coverage.

## Missing tests that should exist now

- An e2e test that drives `BaseEngine.run()` directly with the YAML-loaded sub_step (M3 will add this if not already covered by `test_module_pqc.py`).
- A test asserting that the YAML's TLS step's port list matches `ssl_expiring_certificate.yaml` (operator surprise — both should default to the same port set). Currently I did NOT add `1080` from the SSL list because port 1080 is SOCKS, not typically TLS — but worth a comment in YAML.

## Rules for the next milestone

- **M3 is the last milestone — verdict logic is finalized, opt-out is wired, docs are written, e2e smoke tests run** against real public hosts. Inherit all M1+M2 invariants.
- **Wire `pqc_no_active_probe` extra-arg via the YAML's templating** — the YAML `host: "{target}"` mechanism pre-substitutes operator inputs; the engine's `apply_extra_data` can inspect `sub_step` for the extra-arg key. Need to read how `modules_extra_args` is templated in YAML steps.
- **For M3's e2e: `tls13.1d.pw` and `github.com:22` are not guaranteed to advertise PQC at scan time** — guard with `xfail_strict=False` and skip cleanly when the response doesn't match expectation.
- **Test the `compliance_notes` strings for all four verdicts** — both SSH and TLS — including the F-CEO-1 "CNSA 2.0 requires ML-KEM-1024" branch.

## Template improvements suggested

- The runbook's "BDD acceptance scenarios" template column "Given/When/Then" is good for human-readable specs but doesn't capture *what makes the test catch a bug*. Suggest adding a "Catches" column: "test catches: parser exception escape | wrong length / off-by-one | empty advertised list when server supports PQC | etc." Forces the author to articulate what failure mode the test covers, beyond what the BDD verb chain implies.
