# Lessons Learned — pqc-scanner Milestone 1

## What changed

Added a passive SSH PQC posture probe to OWASP Nettacker. New `pqc_scan` module (YAML + Python library + Engine) reads SSH MSG_KEXINIT off the wire and reports advertised PQ KEX algorithms with a per-host verdict. M1 ships SSH-only; TLS active probe lands in M2.

## Design decisions and why

- **Read SSH KEXINIT one byte at a time for the banner** — read banners in 64-byte chunks initially, but `_read_ssh_banner` over-consumed into the next packet whenever the server sent banner+KEXINIT back-to-back (which fast servers always do). The fix is byte-at-a-time reads bounded by the 255-byte banner cap; this is what OpenSSH does on the wire. Discovered by xdist-parallel test failures that didn't reproduce in serial single-test mode.
- **Module file naming follows Nettacker's `<library>_<action>` ↔ `modules/<action>/<library>.yaml` rule** — initially named `pqc_scan.yaml` mirroring the module name; `TemplateLoader.open()` parses the module name and loads `modules/scan/pqc.yaml`. Renamed to align with the existing `port.yaml`, `ssl_expiring_certificate.yaml`, `ssh.yaml` patterns.
- **Library catches every recoverable network exception** (F-ENG-1) — `BaseEngine.run()` retries on uncaught `Exception` up to `options['retries']` times. For probes this would fan out connection counts against fragile targets. Library wraps the entire probe in a try/finally that converts `socket.timeout`, `ConnectionRefusedError`, `socket.gaierror`, `OSError`, `ValueError`, `UnicodeDecodeError` into `verdict=unknown` + `errors=[...]` — so framework retries become a no-op for probe failures.
- **RFC 4250 §6 charset validation at parse boundary** (F-SEC-1, CWE-117) — server-controlled algorithm-name strings inside MSG_KEXINIT can contain newlines or arbitrary bytes; logging them raw enables log injection. `_safe_ssh_name()` regex-matches `^[A-Za-z0-9._@+/-]+$` and drops non-conformant strings into the `errors` list with a hex-prefix instead.

## Assumptions verified

- Web UI auto-discovery is real — `nettacker/api/engine.py:204` calls `scan_methods()` which delegates to `ArgParser.load_modules()` which globs `Config.path.modules_dir.glob("**/*.yaml")`. **No Web UI manifest edit needed for M3.**
- `ignored_core_modules` rule works as documented — adding `"pqc_scan"` to the list at [nettacker/core/module.py:48-58](../../../nettacker/core/module.py#L48-L58) lets the module run without prior `port_scan` results. Verified by `TestPqcModuleRegistration::test_pqc_scan_in_ignored_core_modules`.
- SSH KEXINIT format per RFC 4253 §7.1: `byte msg_type=20`, 16-byte cookie, 10 name-list strings, 2 booleans, uint32 reserved. Implemented in `_parse_ssh_kexinit()` and verified against canned packet bytes in `TestParseSshKexinit`.

## Assumptions still unresolved

- **Python 3.14 baseline drift** — system has Python 3.14 only; pyproject pins `python = "^3.10, <3.13"`. Two pre-existing tests in `tests/core/lib/test_ssl.py` and `tests/core/lib/test_socket.py` patch `ssl.wrap_socket` which was removed in Python 3.12. Two pre-existing tests in `tests/database/test_db.py` flake under xdist parallel on Python 3.14 (also fail on master at this Python version). These are environmental, NOT introduced by M1. CI on official Python 3.10–3.12 will pass them. Decision: deselect them locally, document the deviation, do not block M1 close-out on environmental drift.
- **End-to-end CLI smoke against a real public SSH endpoint** — deferred to M3 when the e2e test file is in scope (per runbook M1 contract: M1 does not ship `tests/e2e/`).

## Mistakes made

- **Initial banner reader chunk-size bug** — used 64-byte chunks for performance, didn't consider that the server may send banner+KEXINIT in a single TCP segment. Took two test re-runs and a direct-Python diagnostic to spot. Cost ~10 minutes.
- **Initial YAML filename** — followed the *module name* (`pqc_scan.yaml`) instead of the *library name* (`pqc.yaml`). Caught by manually invoking `TemplateLoader('pqc_scan', ...).load()` during smoke. Would not have been caught by unit tests because they call `PqcLibrary` directly. **Rule for next milestone**: in BDD tests for any milestone that adds or renames a module YAML, include a `TemplateLoader` round-trip assertion.

## Root causes

- The chunk-size bug came from optimizing prematurely (banner reads happen once per probe; byte-at-a-time is fine).
- The filename bug came from mirroring the module name instead of reading the loader source first. Fix: always read `nettacker/core/template.py` before authoring a new module.

## What was harder than expected

- **xdist parallel test runs surfaced timing-dependent server bugs that serial tests didn't catch** — the banner over-read bug. Worth keeping xdist on for new tests; it's the canonical way Nettacker's test suite runs.
- **Dependency-install on Python 3.14** — apsw, paramiko, uvloop all needed slightly newer versions than pyproject pins. Local `.venv` workaround kept everything reversible without modifying pyproject.

## Invariants/assertions added or strengthened

- `assert len(SSH_PQC_KEX_ALGORITHMS) <= 4` at module-import time (runbook M1 contract resource bound).
- `_SSH_NAME_RE` enforces RFC 4250 §6 charset at every server-name parse boundary.
- `_read_ssh_packet` rejects `packet_length == 0 or > 35000` per RFC 4253 §6.
- `_read_ssh_banner` rejects banners that hit 255 octets without a terminator.
- `_parse_ssh_kexinit` rejects payloads shorter than `1 + 16` bytes (msg type + cookie minimum).
- `Verdict` typed via `typing.Literal["pqc_ready","hybrid_only","classical_only","unknown"]` — invalid states unrepresentable per Carmack §4.5.

## Resource bounds established or verified

- Banner read: ≤255 bytes (RFC 4253 §4.2).
- KEXINIT packet read: ≤35,000 bytes (RFC 4253 §6.1).
- SSH PQC algorithm table: ≤4 entries v1 cap.
- TCP connections per probe: exactly 1 (one host:port → one connect).
- File descriptors: every probe code path closes its socket; tests assert `psutil.Process().num_fds()` delta is zero across success and failure paths.

## Debugging / inspection notes

- Used direct `python -c` invocation to surface the actual `errors` list when pytest assertions weren't informative (`scan_succeeded=False` doesn't tell you WHY). Lesson: write tests that assert on the error string when `scan_succeeded=False`, not just the boolean.
- The xdist parallel tests can hide timing bugs that show up sequentially. Run new tests both ways during development.

## Naming conventions established

- Library file: `nettacker/core/lib/pqc.py`. Class: `PqcLibrary` and `PqcEngine`. YAML: `nettacker/modules/scan/pqc.yaml`. Module name: `pqc_scan`.
- Response field naming: `<service>_pqc_<aspect>_advertised` (e.g., `ssh_pqc_kex_advertised`, `tls_pqc_groups_advertised`). Mirror name in `<service>_classical_<aspect>_advertised`.
- Error strings: lowercase snake_case identifiers, optionally suffixed with `:<hex>` or `:<exception_class_name>` for diagnostics.

## Test patterns that worked well

- The `_FakeSshServer` context manager: bind 127.0.0.1:0, run a single-shot accept-and-reply thread, replay canned KEXINIT bytes for one of N modes. Reusable across `test_pqc.py` and `test_module_pqc.py`.
- FD-leak parameterized test that re-uses every fake-server mode — minimal extra code, broad coverage for CWE-404.
- "Library never raises" test that explicitly enumerates pathological inputs (closed port, port 0, unroutable IP) and asserts no exception escapes — concrete F-ENG-1 evidence.

## Missing tests that should exist now

- `TemplateLoader('pqc_scan', ...).load()` round-trip — would have caught the YAML filename bug. Adding a check in `test_module_pqc.py` for M2 close-out would make sense even though M1's contract is technically met.
- A test that exercises the actual `BaseEngine.run()` path (not a mock of it) to confirm the framework integration end-to-end. Currently `TestPqcScanModuleEndToEnd` mirrors `BaseEngine.run` manually — adequate for M1, but a real `engine.run(sub_step, ...)` call with a mocked DB would be stronger.

## Rules for the next milestone

- **Read `nettacker/core/template.py` before authoring or renaming any module YAML** (filename convention).
- **For any new TLS or SSH probe, the banner / record reader MUST not over-consume into the next packet** — byte-at-a-time or length-prefixed reads only. M2's TLS 1.3 record framing is length-prefixed by definition (RFC 8446 §5.1) so this is already structurally safe, but the discipline transfers.
- **Use direct `python -c` diagnostic invocations early when pytest assertions aren't informative.**
- **Run new tests under both serial and xdist-parallel modes before commit** — xdist surfaces timing bugs.
- **Honor the F-ENG-1 invariant in M2**: every recoverable network exception must be caught inside the library so the framework retry loop is a no-op for probe failures.
- **Honor the F-SEC-1 invariant in M2**: server-controlled bytes never reach log lines unsanitized. TLS extension data doesn't have algorithm-name strings the way SSH does, but ServerHello selected_group codepoints get rendered to strings via the table — those strings are operator-trusted constants, not server-controlled, so this is OK.
- **Add `psutil` as a `pytest` extra (test-only) if it isn't already pulled in transitively** — the FD-leak tests skip cleanly when not installed; consider making it a soft requirement.

## Template improvements suggested

- The runbook's "Default unit test command" assumes `poetry run pytest`. When `poetry` is unavailable but the deps install via plain `pip`, the command is `.venv/bin/pytest`. Suggest the v4 template add a "Default test command (without poetry)" alternate row for projects where contributors might not have poetry installed.
