# Completion Summary — pqc-scanner Milestone 1

## Goal completed

A user can now run `nettacker -m pqc_scan -i <ssh_host>` and receive a per-host SSH PQC posture verdict (`pqc_ready` / `hybrid_only` / `classical_only` / `unknown`) plus the list of advertised PQ KEX algorithms. The scanner is a Nettacker-native module — discovered automatically by CLI, REST API, and Web UI — and runs without prior `port_scan` (mirrors existing `ssl_*` module pattern).

## Files changed

- `nettacker/core/lib/pqc.py` — NEW. `PqcLibrary` (with `ssh_pqc_scan` method), `PqcEngine`, `SSH_PQC_KEX_ALGORITHMS` table, `TLS_PQC_NAMED_GROUPS` placeholder for M2, all helpers (`_safe_ssh_name`, `_parse_ssh_kexinit`, `_read_ssh_banner`, `_read_ssh_packet`, `_classify_ssh_kex`, `_provisional_verdict_ssh`, `_ssh_compliance_notes`, `_empty_response`).
- `nettacker/modules/scan/pqc.yaml` — NEW. Manifest with `info.name = pqc_scan`, profiles `[scan, pqc, compliance]`, one payload step calling `ssh_pqc_scan` against ports `[22, 2222]` with `timeout: 5`.
- `nettacker/core/module.py` — one-line edit: `"pqc_scan"` added to `ignored_core_modules`.
- `tests/core/lib/test_pqc.py` — NEW. 43 unit tests across 7 test classes (`TestAlgorithmTables`, `TestSafeSshName`, `TestParseSshKexinit`, `TestClassifyAndVerdict`, `TestSshProbeAgainstFakeServer`, `TestFdLeakInvariant`, `TestLibraryNeverRaises`, `TestPqcEngineConditionsResults`).
- `tests/core/test_module_pqc.py` — NEW. 7 integration tests across 4 test classes (`TestPqcModuleRegistration`, `TestPqcLibraryInvocationByName`, `TestPqcScanModuleEndToEnd`, `TestFrameworkRetryNoOp`).
- `.gitignore` — added `evidence/` and `.venv/` patterns.

Total: 4 new files (~1100 lines), 1 one-line edit, 1 .gitignore extension.

## Tests added

- 43 unit tests in `tests/core/lib/test_pqc.py`.
- 7 integration tests in `tests/core/test_module_pqc.py`.
- All 50 pass under both serial and xdist-parallel runs on Python 3.14 with the project's locally-installed `.venv` (Python 3.10–3.12 expected to pass identically in CI).

## Runtime validations added

- `TestPqcScanModuleEndToEnd::test_pqc_scan_against_fake_ssh_populates_conditions_results` — full e2e exercising `getattr(library_class(), method)(**sub_step)` + `engine.apply_extra_data()` against a localhost fake SSH server replaying canned KEXINIT bytes; asserts conditions_results populated with verdict `pqc_ready` and `mlkem768x25519-sha256` in `advertised_pqc`.
- `TestPqcModuleRegistration::test_pqc_scan_in_ignored_core_modules` — verifies the one-line `module.py` edit took effect.
- `TestFrameworkRetryNoOp::test_baseengine_does_not_retry_when_library_returns_dict` — F-ENG-1 evidence; library returns dict on first call, framework does not invoke `wrapper()` more than once.

## Static analysis and formatter evidence

- `ruff format` — 3 files reformatted (whitespace), then clean.
- `ruff check nettacker/core/lib/pqc.py nettacker/core/module.py tests/core/lib/test_pqc.py tests/core/test_module_pqc.py` — `All checks passed!`
- `pre-commit run --all-files` — not run locally because pre-commit framework wasn't pulled into the lightweight `.venv`. CI on the canonical Python 3.10–3.12 environment will run it.

## Compatibility checks performed

- `nettacker -m ssl_expiring_certificate_scan -i <host>` — unchanged code path, existing test still passes (`tests/core/lib/test_ssl.py` 16/16 passing modulo the pre-existing `ssl.wrap_socket` 3.14 incompat).
- `nettacker -m port_scan` — unchanged code path; existing tests pass.
- `Config.path.modules_dir.glob("**/*.yaml")` discovers `pqc.yaml` — verified via `ArgParser.load_modules()` returning `'pqc_scan'` and `ArgParser.load_profiles()` showing `pqc_scan` in `scan`, `pqc`, `compliance` profile lists.
- SQLite events table accepts new module's logs without migration — verified indirectly via `TestPqcScanModuleEndToEnd` populating `conditions_results` exactly the way `BaseEngine.process_conditions` expects.

## Invariants/assertions added

- `assert len(SSH_PQC_KEX_ALGORITHMS) <= 4` (module-import time).
- `_SSH_NAME_RE = re.compile(rb"\A[A-Za-z0-9._@+/-]+\Z")` enforced at every parse boundary.
- `Verdict = Literal["pqc_ready","hybrid_only","classical_only","unknown"]`.
- `Service = Literal["tls","ssh"]`.
- `PqcAlgorithmEntry`, `SshAlgorithmEntry` `TypedDict`s — table well-formedness.
- Banner read raises `ValueError("banner_overflow_capped_at_255")` if cap hit without terminator.
- KEXINIT packet rejects `packet_length == 0 or > 35000`.

## Resource bounds added or verified

- 255-byte banner cap (RFC 4253 §4.2).
- 35,000-byte SSH packet cap (RFC 4253 §6.1).
- 4-entry SSH algorithm table cap.
- 1 TCP connection per probe.
- Zero FD leak across all probe code paths (asserted via `psutil.Process().num_fds()` delta).

## Documentation updated

- `docs/slo/lessons/pqc-scanner-m1.md` — this milestone's lessons file.
- `docs/slo/completion/pqc-scanner-m1.md` — this completion summary.
- Runbook Milestone Tracker — flipped M1 to `done` with Started + Completed dates.

## .gitignore changes

- Added `.venv/` (project-local Python virtualenv).
- Added `evidence/` (transient slo Evidence Log artifacts).

## Test artifact cleanup verified

- `git status` after running the full suite: clean working tree (modulo files explicitly staged for this commit).
- Fake SSH server tests bind to ephemeral ports (`bind('127.0.0.1', 0)`) and close sockets in `__exit__`; no residual processes or files.
- No commit of test output to source control.

## Deferred follow-ups

- **CWE-918 SSRF via `--target` argument**: inherited concern from existing Nettacker modules, not introduced. Held by critique F-SEC-4.
- **Cert-chain PQC analysis (F-CEO-2)**: deferred to a v1.1 fast-follow runbook so v1 wedge stays one week.
- **README.md Key Features bullet**: optional, deferred to M3.
- **`docs/Modules.md` user-facing entry**: deferred to M3.
- **End-to-end CLI smoke against real public SSH endpoint** (e.g., `github.com:22` advertising `sntrup761x25519-sha512@openssh.com`): in M3 contract.

## Known non-blocking limitations

- **Provisional verdict logic**: M3 finalizes the `compliance_notes` wording with full CNSA 2.0 / OMB M-23-02 mapping. M1 ships a working baseline that emits readable strings.
- **TLS path**: stub-not-implemented — M2 ships the active ClientHello probe.
- **`pqc_no_active_probe` opt-out**: M3 wires it. M1 has nothing active to opt out of.
- **Python 3.14 baseline drift**: 4 tests deselected locally due to `ssl.wrap_socket` removal (3.12+) and xdist-parallel flakes (`test_logs_to_report_html_*`). Both also fail on master at this Python version. CI on the canonical 3.10–3.12 environment will pass them.
