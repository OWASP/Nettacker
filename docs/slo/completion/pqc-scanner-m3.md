# Completion Summary — pqc-scanner Milestone 3

## Goal completed

The `pqc_scan` module is **shippable**. A user can run `nettacker -m pqc_scan -i <target>` and receive a per-host TLS+SSH PQC posture verdict mapped to NIST FIPS 203 / OMB M-23-02 / CNSA 2.0 baselines. The active TLS probe is operator-disablable via `--modules-extra-args pqc_no_active_probe=true` for fragile environments. End-to-end CLI smoke tests pass against `github.com:22` (advertises `sntrup761x25519-sha512@openssh.com`) and `pq.cloudflareresearch.com:443` (advertises `X25519MLKEM768`).

## Files changed

- `nettacker/core/lib/pqc.py` — finalized `_tls_compliance_notes` wording; added `_is_truthy_extra_arg`; added `PqcEngine.run` override implementing the `pqc_no_active_probe` opt-out; switched to empty `KeyShareClientHello` per RFC 8446 §4.2.8 (M3 correctness fix surfaced by e2e).
- `tests/core/lib/test_pqc.py` — added `TestIsTruthyExtraArg`, `TestComplianceNotesFinalWording`, `TestPqcNoActiveProbeOptOut`, `TestProvisionalVerdictPqcReadyInvariant`. Updated `test_clienthello_uses_empty_key_share_for_hrr_signal` (was `test_clienthello_key_share_payload_zero_filled` in M2).
- `tests/e2e/test_pqc_scan_smoke.py` — NEW. 3 network-dependent smoke tests with `_tcp_reachable()` pre-check + `NETTACKER_NO_NETWORK_TESTS` skip env-var.
- `tests/e2e/__init__.py` — NEW (empty marker).
- `docs/Modules.md` — added the `pqc_scan` entry in the Scan Modules list, plus a 140+ line `## PQC Compliance Scanner (pqc_scan)` section with quick-start examples, verdict table, safety model, compliance-mapping table, known limitations, and output JSON schema.
- `README.md` — added a Key Features bullet linking to `docs/Modules.md`.
- `docs/RUNBOOK-pqc-compliance-scanner.md` — flipped M3 tracker row to `done`.
- `docs/slo/lessons/pqc-scanner-m3.md` + `docs/slo/completion/pqc-scanner-m3.md` — this milestone's lessons + completion files.

Total: ~290 new lines of production / test code + ~145 lines of user-facing documentation.

## Tests added

- 4 new unit/integration test classes: `TestIsTruthyExtraArg` (16 parametrized cases), `TestComplianceNotesFinalWording` (7 tests), `TestPqcNoActiveProbeOptOut` (3 tests), `TestProvisionalVerdictPqcReadyInvariant` (2 tests). 28 tests total in M3.
- 3 e2e smoke tests in `tests/e2e/test_pqc_scan_smoke.py`.
- All 31 new tests pass. PQC suite total: 118 unit/integration tests + 3 e2e = 121 tests, vs M2 closeout's 91 + 7 = 98 (net +23, replacing the 1 stale M2 zero-buffer-payload test).

## Runtime validations added

- `TestPqcNoActiveProbeOptOut::test_opt_out_short_circuits_tls_probe_no_network_call` — tripwire test verifies the library is NOT invoked when opt-out is on.
- `TestPqcNoActiveProbeOptOut::test_opt_out_does_not_affect_ssh_path` — SSH path still runs under opt-out.
- `TestPqcNoActiveProbeOptOut::test_opt_out_off_runs_tls_path_normally` — sanity: no opt-out → TLS runs.
- `tests/e2e/test_pqc_scan_smoke.py::test_smoke_ssh_pqc_against_github_or_gitlab` — real `github.com:22` (or gitlab fallback) probe.
- `tests/e2e/test_pqc_scan_smoke.py::test_smoke_tls_pqc_against_known_pq_endpoint` — real Cloudflare PQ endpoint probe.
- `tests/e2e/test_pqc_scan_smoke.py::test_smoke_tls_pqc_does_not_hang_on_loopback_no_listener` — non-network sanity that closed-port path returns within timeout.

## Static analysis and formatter evidence

- `ruff format nettacker/core/lib/pqc.py tests/core/lib/test_pqc.py tests/e2e/test_pqc_scan_smoke.py` — clean (3 files left unchanged after format).
- `ruff check nettacker/core/lib/pqc.py tests/core/lib/test_pqc.py tests/core/test_module_pqc.py tests/e2e/test_pqc_scan_smoke.py` — `All checks passed!`

## Compatibility checks performed

- M1 SSH probe still works — all M1 tests pass.
- M2 TLS probe still works (with the empty-`key_share` correctness fix). `test_clienthello_uses_empty_key_share_for_hrr_signal` updates the M2 test that asserted the obsolete zero-buffer payload.
- Existing `ssl_*` modules untouched.
- `make test` baseline (minus the 4 pre-existing-on-master Python-3.14-environmental flakes): **447 passed**, 7 skipped, 0 unexpected failures.
- `nettacker -m pqc_scan --help` works (verified manually).
- Web UI auto-discovery still works (no changes to `nettacker/web/` or `nettacker/api/engine.py`).

## Invariants/assertions added

- F-CEO-1 invariant: `pqc_ready` ⇒ ≥1 advertised algorithm has `status="standardized"`. Pinned by `TestProvisionalVerdictPqcReadyInvariant` for every entry in both SSH and TLS tables.
- Opt-out invariant: `pqc_no_active_probe=true` + method=`tls_pqc_scan` ⇒ library NOT invoked. Tripwire test.
- Compliance-notes invariant: every `pqc_ready` TLS note cites FIPS 203; every `classical_only` TLS note cites OMB M-23-02; every `pqc_ready` SSH note cites OpenSSH 10.1 baseline.

## Resource bounds added or verified

- No new bounds (all M1 + M2 bounds inherited).
- Opt-out path: probe count drops from 6 (5 TLS + 1 SSH) to 1 (SSH only).

## Documentation updated

- `docs/Modules.md` — module list entry + dedicated `## PQC Compliance Scanner` section (the user-facing entry per runbook M3 contract).
- `README.md` — Key Features bullet.
- `docs/slo/lessons/pqc-scanner-m3.md` — this milestone's lessons.
- `docs/slo/completion/pqc-scanner-m3.md` — this completion summary.
- Runbook Milestone Tracker — M3 → `done`.

## .gitignore changes

- None.

## Test artifact cleanup verified

- Fake servers in unit tests bind ephemeral ports + close in `__exit__`.
- E2E smoke tests do not write any files.
- `git status` after running the full suite: clean working tree (modulo files staged for this commit).

## Deferred follow-ups

- **F-CEO-2 (cert-chain PQC)**: separate v1.1 runbook.
- **SSH host-key PQ algorithm enumeration**: v2 (waiting on OpenSSH PQ signature support).
- **ML-KEM-512 in the table**: v2 (no compliance framework requires it).
- **`pqcscan`-style standalone HTML report**: v2 (Nettacker's existing report formats are sufficient for v1).
- **DORA Article 28 explicit citation in compliance_notes**: v1.1 docs polish.

## Known non-blocking limitations

- TLS probes use empty `KeyShareClientHello` (RFC 8446 §4.2.8). A non-conformant server that closes the connection on missing `key_share` would be reported as `unknown` with a `tcp_closed_<group>` error — not as `classical_only`. RFC-conformant servers (OpenSSL, BoringSSL, Rust rustls, NSS, JSSE) handle this correctly.
- E2E smoke tests depend on third-party hosts (`github.com:22`, `pq.cloudflareresearch.com:443`). They skip cleanly when unreachable; CI on a network-restricted runner should set `NETTACKER_NO_NETWORK_TESTS=1`.
- v1 does not analyze TLS certificate chains for PQ signatures. A server can advertise X25519MLKEM768 yet present an RSA-2048 cert chain; `pqc_scan` reports `pqc_ready` (per the KEM advertisement) but the operator should also run `ssl_certificate_scan` for the cert-chain side. Documented in `docs/Modules.md` § "Known v1 limitations".

## Final branch state at M3 close

7 commits on `feature/pqc-compliance-scanner`:
1. `b801c9ab` — design artifacts (idea/research/architect outputs)
2. `db1943bb` — v4 runbook
3. `ab734356` — critique + applied 8/9 asks
4. `1d9ca6a6` — M1 implementation (initial)
5. `2adef67b` — M1 closeout (banner-reader fix, YAML rename, lessons)
6. `07d9dfc5` — M2 (TLS 1.3 active probe + algorithm table + tests)
7. _next_ — M3 (verdict finalization, opt-out, docs, e2e smoke, M2 correctness fix)

Ready for `/slo-ship` to open the PR.
