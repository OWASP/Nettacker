# Lessons Learned — pqc-scanner Milestone 3

## What changed

- Finalized `_tls_compliance_notes` wording with FIPS 203 + CNSA 2.0 + OMB M-23-02 citations. ML-KEM-1024 advertised → "meets CNSA 2.0 ML-KEM-1024 baseline". ML-KEM-768-only / hybrid → "transitional — CNSA 2.0 requires ML-KEM-1024 by 2027-01-01" (F-CEO-1 honest mapping).
- Added `_is_truthy_extra_arg` helper and `PqcEngine.run` override that short-circuits the active TLS probe when the operator passes `--modules-extra-args pqc_no_active_probe=true`. SSH passive probe still runs. Threat-model abuse-1 (fragile-LB) mitigation is now wired end-to-end.
- Added `tests/e2e/test_pqc_scan_smoke.py` — three network-dependent smoke tests against `github.com:22` (or fallback gitlab.com) and `pq.cloudflareresearch.com:443`. Marked `@pytest.mark.e2e`. Skip cleanly when `NETTACKER_NO_NETWORK_TESTS=1` or when the named endpoint is unreachable.
- Added user-facing `## PQC Compliance Scanner (pqc_scan)` section in `docs/Modules.md` (140+ lines) covering quick-start, verdict table, what we probe, safety operating model, compliance-mapping table, known v1 limitations, output JSON schema.
- Added a Key Features bullet to `README.md` advertising the new module.

**Critical correctness fix discovered by M3 e2e**: M2 emitted a TLS ClientHello with `key_share` containing an all-zero buffer of the IETF-pinned length. Real-world e2e against `pq.cloudflareresearch.com:443` returned `decode_error_for_X25519MLKEM768` — Cloudflare's PQ research server validates the *content* of the client's key_share, not just the length. The all-zero buffer fails decode validation, producing a false-negative `classical_only` verdict on a server that actually supports PQ. Switched to **empty `KeyShareClientHello`** (zero entries, RFC 8446 §4.2.8 explicitly allows it). Server now correctly replies with HelloRetryRequest specifying the supported group, and the scanner reports `pqc_ready` for Cloudflare. Verified live against both `pq.cloudflareresearch.com` and `cloudflare.com`.

## Design decisions and why

- **Override `PqcEngine.run` rather than templating the YAML with `{pqc_no_active_probe}`** — the `format(**module_inputs)` substitution path requires the key to always be present in module_inputs. Adding it as a globally-registered argparse default would expose a CLI flag we don't want to advertise. The engine's `options` parameter (which is `module_inputs`) is the natural place to read the extra-arg, and `dict.get` returns `None` when absent. Cleaner separation of concerns.
- **Empty `key_share` over zero-buffer key_share** — chose the more spec-aligned discovery technique. Under RFC 8446 §4.2.8, empty `client_shares` is valid; the server MUST send HelloRetryRequest specifying the chosen group. This is exactly what we want for posture detection (we never need a real key share because we don't complete the handshake). Avoids server-side content validation entirely. The key_share-bytes-length column in the algorithm table remains useful as documentation but is no longer emitted on the wire.
- **`_is_truthy_extra_arg` helper accepts the typical truthy spellings** — `--modules-extra-args` values arrive as strings. Accept `true`, `1`, `yes`, `on` (case-insensitive, whitespace-trimmed). Reject `false`, empty string, None, bool False. This matches what users intuitively type without locking the contract to one specific string.
- **E2E tests use `_tcp_reachable()` pre-check** — public PQ test endpoints come and go. Pre-checking with a small TCP connect lets us `pytest.skip(reason="...")` cleanly when a host has retired, rather than failing CI. The 3rd e2e test (`test_smoke_tls_pqc_does_not_hang_on_loopback_no_listener`) is intentionally non-network — exercises the TCP-refused → `unknown` path without depending on internet.

## Assumptions verified

- The empty-`key_share` technique works against real TLS 1.3 servers. Verified live: `pq.cloudflareresearch.com` and `cloudflare.com` both correctly reply with HRR specifying X25519MLKEM768 → scanner reports `pqc_ready`.
- The `pqc_no_active_probe` opt-out is honored without invoking the library — verified by tripwire test (`test_opt_out_short_circuits_tls_probe_no_network_call`) that fails the test if `tls_pqc_scan` is called.
- The opt-out does NOT affect the SSH path — `test_opt_out_does_not_affect_ssh_path` confirms.
- F-CEO-1 invariant: `pqc_ready` ⇒ ≥1 advertised algorithm has `status="standardized"`. Pinned by `TestProvisionalVerdictPqcReadyInvariant` for both SSH and TLS paths.
- Modules.md renders cleanly as Markdown (visual review).

## Assumptions still unresolved

- **CNSA 2.0 mapping**: the runbook + tests assert "MLKEM1024 advertised → meets CNSA 2.0 baseline". This is true for the *KEM* requirement. CNSA 2.0 also requires ML-DSA-87 for signatures, AES-256, SHA-384/512. The scanner doesn't probe signatures or symmetric crypto — those are out of v1 scope. The compliance_notes wording should arguably be more conservative ("meets CNSA 2.0 KEM requirement"). Left as a docs polish for v1.1.
- **DORA Article 28 mapping**: README mentions DORA but the compliance_notes don't cite DORA-specific articles. v1.1 / v2 territory.
- **Public PQ test endpoint stability**: `pq.cloudflareresearch.com` was reachable + advertising X25519MLKEM768 at scan time. If Cloudflare retires the test server, the e2e test skips cleanly but the smoke loses coverage.

## Mistakes made

- **All-zero key_share design choice in M2 was a real false-negative bug**, not just a "limitation to document." M2 documented the trade-off but didn't fix it; M3 e2e against a real server forced the fix. Lesson: design choices that are documented as known limitations should be re-evaluated at every later milestone — they may be cheaper to fix than to ship.

## Root causes

- The all-zero key_share bug came from optimizing for "no liboqs dependency" without considering that conformant TLS implementations would validate key content. The empty-key_share fix is *equally* dependency-free AND avoids the validation issue. Better-designed primitive was hiding in plain sight in RFC 8446 §4.2.8 — should have been the M2 default.

## What was harder than expected

- **`PqcEngine.run` override required mirroring `BaseEngine.run`'s shape almost line-for-line** — the `submit_logs_to_db` call has a specific contract that the framework expects. The opt-out test had to monkey-patch both `submit_logs_to_db` and `submit_temp_logs_to_db` to avoid SQLite side-effects in unit tests. Worth documenting that engines overriding `run` need to preserve the conditions-results / process_conditions flow.

## Invariants/assertions added or strengthened

- F-CEO-1 invariant pinned by `TestProvisionalVerdictPqcReadyInvariant`: `pqc_ready` ⇒ at least one advertised algorithm has `status="standardized"`. Tested for every entry in both SSH and TLS tables.
- `compliance_notes` strings invariant: every verdict's compliance note cites the relevant standard (FIPS 203, OpenSSH 10.1, OMB M-23-02, CNSA 2.0). Tested by string-matching assertions in `TestComplianceNotesFinalWording`.
- Opt-out invariant: `pqc_no_active_probe=true` + method=`tls_pqc_scan` ⇒ library not invoked. Tested by tripwire.

## Resource bounds established or verified

- No new resource bounds introduced (all M1 + M2 bounds inherited).
- The opt-out path bypasses TLS probes entirely → reduces probe count from `len(TLS_PQC_NAMED_GROUPS) + 1 SSH = 6` to `1 SSH only`. Operator's escape hatch for fragile environments.

## Debugging / inspection notes

- `pdb`-stepped through the verdict-logic boundary case (`pqc_ready` for `MLKEM768` only — should be `pqc_ready` per spec but with a transitional `compliance_notes`). Confirmed the F-CEO-1 invariant holds.
- Live-probed `pq.cloudflareresearch.com` and `cloudflare.com` with both the M2 (zero-buffer key_share) and M3 (empty key_share) implementations. Captured the `decode_error` → `pqc_ready` transition in the M3 lessons.

## Naming conventions established

- E2E test files: `tests/e2e/test_<module>_smoke.py`, marked `@pytest.mark.e2e`.
- E2E skip env-var: `NETTACKER_NO_NETWORK_TESTS=1` — uppercase, env-var-style.
- Module docs section header in `docs/Modules.md`: `## PQC Compliance Scanner (\`<module_name>\`)` — full module name in code-fences for searchability.

## Test patterns that worked well

- **`_tcp_reachable()` pre-check + `pytest.skip` on no-network** — robust e2e that doesn't break CI when a third-party endpoint changes.
- **Tripwire test** for opt-out (`def tripwire(*a, **kw): raise RuntimeError(...)`) — strongest possible signal that the library is NOT invoked.
- **String-match assertions on `compliance_notes`** — catches "did you forget to mention CNSA 2.0?" without overconstraining the wording.

## Missing tests that should exist now

- A test that exercises the FULL `BaseEngine.run` → `PqcEngine.run` override path with the SQLite DB connected (currently we monkey-patch `submit_logs_to_db`). Would require integration-test infrastructure that's heavier than M3's scope.
- A test that confirms ML-DSA-87 signature support — out of v1 scope (we don't probe signatures), but worth tracking for v2.

## Rules for the next milestone

- **There is no next milestone in this runbook.** M3 closes the wedge. Subsequent work happens in fresh runbooks:
  - **v1.1**: `tls_cert_pqc_scan` (cert-chain PQ analysis cross-referencing `ssl_certificate_scan` results — F-CEO-2 deferral).
  - **v2**: SSH host-key PQ algorithm enumeration (when OpenSSH ships PQ signature algos).
  - **v2**: ML-KEM-512 in the table if a compliance framework ever requires it.
  - **v2**: `pqcscan`-style HTML report generation (currently we rely on Nettacker's existing report formats).

## Template improvements suggested

- The slo-execute skill says "If a failure is not explained by compiler, test assertion, or stack trace, use a debugger or equivalent state-inspection tool before making speculative changes." For network-dependent tests, this should also include "exercise the code path against a real endpoint with a `python -c` smoke" — the all-zero key_share bug was discovered exactly this way and would NEVER have surfaced from unit tests alone. Worth promoting "live smoke probes" as an explicit debugging tool.
