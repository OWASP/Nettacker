# PQC Compliance Scanner — OWASP Nettacker (AI-First Runbook v4)

> **Purpose**: Add a `pqc_scan` Nettacker module that probes a TLS 1.3 or SSH endpoint for advertised post-quantum cryptography algorithms (ML-KEM family, X25519MLKEM768, mlkem768x25519-sha256, sntrup761x25519-sha512) and emits a per-host posture verdict (`pqc_ready` / `hybrid_only` / `classical_only` / `unknown`).
> **Audience**: AI coding agents first, humans second.
> **Core philosophy**: Light + reliable beats feature-rich. No completed handshakes. No new system deps. Strict RFC 8446 / RFC 4253 conformance. Operator opt-out for fragile environments.
> **How to use**: Work milestones sequentially. Every milestone runs the Global Entry Protocol then the Global Exit Protocol. Allow-lists are not negotiable.
> **Prerequisite reading**: [docs/CodebaseOverview.md](CodebaseOverview.md), [docs/Developers.md](Developers.md), [docs/Modules.md](Modules.md), [AGENTS.md](../AGENTS.md), [docs/slo/design/pqc-compliance-scanner-overview.md](slo/design/pqc-compliance-scanner-overview.md), [docs/slo/design/pqc-compliance-scanner-stack-decision.md](slo/design/pqc-compliance-scanner-stack-decision.md), [docs/slo/design/pqc-compliance-scanner-interfaces.md](slo/design/pqc-compliance-scanner-interfaces.md), [docs/slo/design/pqc-compliance-scanner-security.md](slo/design/pqc-compliance-scanner-security.md), [docs/slo/design/pqc-compliance-scanner-threat-model.md](slo/design/pqc-compliance-scanner-threat-model.md), [docs/slo/research/pqc-compliance-scanner/synthesis.md](slo/research/pqc-compliance-scanner/synthesis.md).

---

## 1. Runbook Metadata

| Field | Value |
|---|---|
| Runbook ID | `pqc-scanner` |
| Project name | `OWASP Nettacker` |
| Primary stack | Python 3.10–3.12, stdlib (`socket`, `struct`, `ssl`), paramiko (existing dep), pyopenssl (existing dep) |
| Primary package/app names | `nettacker` |
| Prefix for tests and lesson files | `pqc-scanner` |
| Default unit test command | `poetry run pytest tests/core/lib/test_pqc.py -v` |
| Default integration/BDD test command | `poetry run pytest tests/core/lib/test_pqc.py tests/core/test_module_pqc.py -v` |
| Default E2E/runtime validation command | `poetry run pytest tests/e2e/test_pqc_scan_smoke.py -v -m e2e` |
| Default build/boot command | `poetry run nettacker --help` |
| Default formatter command | `poetry run ruff format nettacker/core/lib/pqc.py nettacker/modules/scan/pqc_scan.yaml tests/` |
| Default static analysis / lint command | `poetry run ruff check nettacker tests` |
| Default dependency / security audit command | `poetry check && poetry export --without-hashes -f requirements.txt | poetry run pip-audit -r /dev/stdin` (only if deps changed; deps must NOT change in v1) |
| Default debugger or state-inspection tool | `python -m pdb`, `pytest --pdb`, `wireshark` for on-the-wire ClientHello validation |
| Allowed new dependencies by default | `none` |
| Schema/config migration allowed by default | `no` |
| Public interfaces stable by default | `yes` |

### Public interfaces that must remain stable unless explicitly listed otherwise

- The CLI invocation `nettacker -m pqc_scan -i <target>` once introduced in M1.
- The library/engine class names `PqcLibrary`, `PqcEngine` (consumed by Nettacker's auto-discovery loader at [nettacker/core/module.py:156-159](../nettacker/core/module.py#L156-L159)).
- The library method names `tls_pqc_scan`, `ssh_pqc_scan` (referenced from `pqc_scan.yaml`).
- The `verdict` enum values: `pqc_ready` / `hybrid_only` / `classical_only` / `unknown`.
- The response-shape field names listed in [pqc-compliance-scanner-interfaces.md](slo/design/pqc-compliance-scanner-interfaces.md).
- The per-module extra-arg key `pqc_no_active_probe` (boolean, default false).
- All existing Nettacker public CLI flags, module names, and database schema — UNTOUCHED.

---

## 2. Milestone Tracker

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 1 | Foundation + SSH passive PQC probe | done | 2026-05-06 | 2026-05-06 | [pqc-scanner-m1.md](slo/lessons/pqc-scanner-m1.md) | [pqc-scanner-m1.md](slo/completion/pqc-scanner-m1.md) |
| 2 | TLS 1.3 active PQC ClientHello probe | done | 2026-05-06 | 2026-05-06 | [pqc-scanner-m2.md](slo/lessons/pqc-scanner-m2.md) | [pqc-scanner-m2.md](slo/completion/pqc-scanner-m2.md) |
| 3 | Verdict, opt-out, docs, end-to-end smoke | done | 2026-05-06 | 2026-05-06 | [pqc-scanner-m3.md](slo/lessons/pqc-scanner-m3.md) | [pqc-scanner-m3.md](slo/completion/pqc-scanner-m3.md) |

<!-- Status: not_started | in_progress | blocked | done -->
<!-- Lessons: docs/slo/lessons/pqc-scanner-m<N>.md -->
<!-- Completion: docs/slo/completion/pqc-scanner-m<N>.md -->

---

## 3. End-to-End Architecture Diagram

```
                              TRUST BOUNDARY
                             (operator's host)
                                     │
                                     │ internet / internal network
                                     │
┌────────────────────────────────────┼──────────────────────────────────────┐
│ Nettacker process (existing)       │                                      │
│                                    │     ┌──────────────────────────┐     │
│  ┌──────────┐    ┌────────────┐    │     │ Target endpoint          │     │
│  │   CLI    │    │  Web UI    │    │     │  TLS server :443 etc     │     │
│  │(existing)│    │ (existing) │    │     │  SSH server :22 / :2222  │     │
│  └────┬─────┘    └─────┬──────┘    │     └─────▲────────────┬─────-─┘     │
│       └───────┬────────┘           │           │            │             │
│               ▼                    │           │ probe      │ banner +    │
│      ┌─────────────────┐           │           │ (1 conn    │ KEXINIT     │
│      │ Module loader   │           │           │  / group)  │ (1 conn)    │
│      │ core/module.py  │           │           │            │             │
│      └────────┬────────┘           │           │            │             │
│               │ load YAML +        │           │            │             │
│               │ instantiate engine │           │            │             │
│               ▼                    │           │            │             │
│  - - - - - - - - - - - - - - -     │           │            │             │
│  ┊ pqc_scan.yaml (NEW M1)    ┊     │           │            │             │
│  ┊ modules/scan/             ┊     │           │            │             │
│  - - - - - - - - - - - - - - -     │           │            │             │
│               │ method:            │           │            │             │
│               │  ssh_pqc_scan (M1) │           │            │             │
│               │  tls_pqc_scan (M2) │           │            │             │
│               ▼                    │           │            │             │
│  - - - - - - - - - - - - - - -     │           │            │             │
│  ┊ PqcLibrary + PqcEngine    ┊ - ─ ─ ─ ─ raw TCP, ─ ─ ─ ─ ─ ┘             │
│  ┊ core/lib/pqc.py (NEW)     ┊ - ─ ─ ─ ─ stdlib socket  ─ ─ ┘             │
│  ┊  TLS_PQC_NAMED_GROUPS     ┊                                            │
│  ┊  SSH_PQC_KEX_ALGORITHMS   ┊                                            │
│  - - - - - - - - - - - - - - -                                            │
│               │ verdict + advertised list                                 │
│               ▼                                                           │
│      ┌────────────────────────┐                                           │
│      │ BaseEngine.process_    │                                           │
│      │  conditions (existing) │                                           │
│      └────────────┬───────────┘                                           │
│                   │ logs                                                  │
│                   ▼                                                       │
│         ┌─────────────────┐                                               │
│         │ SQLite          │                                               │
│         │ .nettacker/data │                                               │
│         │ /nettacker.db   │                                               │
│         │ (existing)      │                                               │
│         └─────────────────┘                                               │
└───────────────────────────────────────────────────────────────────────────┘

Legend:  ──── existing component       - - - new (this runbook)
         ────► data flow               ─ ─ ─► network call (observation only)
         TRUST BOUNDARY = operator host vs. target endpoint
```

### Component Summary Table

| Component | Responsibility | Existing/New/Changed | Milestone | Key Interfaces |
|---|---|---|---|---|
| `nettacker/modules/scan/pqc_scan.yaml` | Module manifest. Wires CLI invocation → library methods + default port lists. | NEW | M1 (SSH step), M2 (TLS step added) | YAML loaded by `TemplateLoader`. |
| `nettacker/core/lib/pqc.py` | `PqcLibrary` (probe code) + `PqcEngine` (response/verdict). Algorithm tables. | NEW | M1 (skeleton + SSH), M2 (TLS), M3 (verdict + opt-out) | `tls_pqc_scan(host,port,timeout)`, `ssh_pqc_scan(host,port,timeout)`. |
| `nettacker/core/module.py` | Add `pqc_scan` to `ignored_core_modules` so module runs without prior `port_scan`. | CHANGED (one-line edit) | M1 | `Module.__init__` reads `ignored_core_modules`. |
| `tests/core/lib/test_pqc.py` | Unit tests for library methods + table integrity. | NEW | M1, M2, M3 | pytest. |
| `tests/core/test_module_pqc.py` | Module-level integration test with mocked TCP servers. | NEW | M1, M2, M3 | pytest. |
| `tests/e2e/test_pqc_scan_smoke.py` | End-to-end CLI smoke against a known public PQ-ready endpoint. | NEW | M3 | pytest, marked `e2e` (skip in default `make test` if `--no-network` set). |
| `docs/Modules.md` | User-facing module docs. | CHANGED | M3 | Markdown. |

### Data Flow Summary

| Flow | From | To | Protocol/Mechanism | Bounded? | Failure Mode | Milestone |
|---|---|---|---|---|---|---|
| Operator → CLI invocation | CLI | Module loader | argparse | yes (single argv) | argparse error | existing |
| Module loader → PqcEngine | TemplateLoader | `PqcEngine.run()` per step | python import + getattr | yes (one engine per payload) | log warn `library_not_supported` | M1 |
| `PqcLibrary.ssh_pqc_scan` → target | scanner | SSH server :22 / :2222 | TCP → SSH banner exchange + read 1× MSG_KEXINIT | yes (1 conn per (host,port), bounded read) | timeout → `verdict=unknown` + `errors=[…]` | M1 |
| `PqcLibrary.tls_pqc_scan` → target | scanner | TLS server :443 etc | TCP → 1× TLS 1.3 ClientHello per probed group → read 1× record | yes (≤8 conns per (host,port)) | timeout / RST / handshake_failure → recorded per-group, not retried | M2 |
| PqcEngine → SQLite | engine | DB | existing `submit_logs_to_db()` | inherited | inherited | M1 |

---

## 4. Carmack-Style Development Best Practices

(Section 4 verbatim from the v4 template; all rules apply.)

### 4.1 Inspect State, Do Not Guess

| Requirement | Project-Specific Tool/Command | Evidence Required |
|---|---|---|
| Interactive debugger available | `python -m pdb`, `pytest --pdb` | Verified by running `pytest --pdb tests/core/lib/test_pqc.py::test_known_failing_case` |
| Breakpoints can be set in changed code | `breakpoint()` in `pqc.py` source | Note breakpoint hit in lessons file when used |
| Runtime state can be inspected | `pdb` prompt shows `socket_connection`, `recv_buffer`, `parsed_kexinit` | Inspect at least one failing scenario per milestone |
| Tests can be debugged | `poetry run pytest --pdb -k <expr>` | Documented in lessons file when used |
| On-wire byte validation | `wireshark` or `tcpdump -i lo -X port 4443` against local mock server | Used at least once in M2 to validate ClientHello shape |

### 4.2 Static Analysis Is Mandatory

| Check | Command | Required Level | Notes |
|---|---|---|---|
| Formatter | `poetry run ruff format <files>` | must pass | Limit to changed files. |
| Type check (light) | `poetry run python -c "import nettacker.core.lib.pqc"` | must pass | Nettacker has no project-wide mypy gate; this is a smoke import. |
| Static analyzer / linter | `poetry run ruff check <files>` | must pass | Project ruff config in `pyproject.toml`; line length 99. |
| Pre-commit hooks | `pre-commit run --all-files` | must pass | Per [AGENTS.md](../AGENTS.md): "Before pushing: `pre-commit run --all-files` and `make test` must pass". |
| Security/dependency audit | `poetry check` | must pass | No new deps in v1 — audit only required if M2/M3 inadvertently adds one. |

### 4.3 Assertions Are Executable Comments

Use assertions for: protocol-frame length invariants (TLS record size ≤ 16384, SSH packet length ≤ 35000), algorithm-table well-formedness (every entry has the required keys), enum bounds on `verdict`. Do not use for: socket failures, server-misbehavior responses (those are recoverable).

### 4.4 Prefer Bounded Resources Over Silent Growth

| Resource | Expected Bound | Hard Limit | Behavior At Limit | Evidence/Test |
|---|---:|---:|---|---|
| Probed PQC named-groups per (host, port) | ≤ 8 | 8 (table-bound in v1) | additional groups never queued because table is fixed-size | `test_pqc_named_groups_table_bounded` |
| TCP connections per (host, port) per scan | = `len(probed_groups) + 1 SSH` | bounded by table | framework's `thread_per_host` further caps concurrency | smoke test in M3 verifies via netstat sample |
| Bytes read per TLS probe | ≤ 16,384 (1 record) | 16,384 | socket closed when limit hit; `errors` records "oversized response" | `test_tls_probe_truncates_oversized_response` |
| Bytes read per SSH probe | ≤ 35,000 (1 packet) | 35,000 | socket closed when limit hit | `test_ssh_probe_truncates_oversized_packet` |
| Banner read length (SSH) | ≤ 255 bytes | 255 | per RFC 4253 §4.2; raise on overflow | `test_ssh_banner_capped` |

### 4.5 Make Invalid States Unrepresentable

| Concept | Prefer | Avoid |
|---|---|---|
| Verdict | a `Verdict` enum / `Literal["pqc_ready","hybrid_only","classical_only","unknown"]` | free-form string |
| Algorithm-table entry | `TypedDict` with required keys `name`, `kind`, `status` | bare dict |
| Service kind | `Literal["tls","ssh"]` | string |
| Probe response classification | tagged union: `("server_hello", group_name)` / `("hello_retry_request", group_name)` / `("alert", level, code)` / `("timeout",)` / `("tcp_closed",)` | nested optionals |

### 4.6 Preserve Compatibility Until Explicitly Broken

Every milestone runs the existing `make test` (full Nettacker suite) before close-out. Existing modules `ssl_expiring_certificate_scan`, `ssh` (brute), `port_scan` etc. MUST keep passing.

### 4.7 Prefer Small, Local, Reviewable Changes

This runbook is one feature touching at most:
- 1 new YAML file
- 1 new Python file
- 1 line added to an existing Python file (`ignored_core_modules`)
- 3 new test files
- 1 new docs section in `docs/Modules.md`

Anything beyond requires explicit milestone-contract authorization.

### 4.8 No Silent Failure

Every per-group probe failure is recorded in the `errors` list of the response. `verdict=unknown` is a visible state, not a silent fallback.

---

## 5. High-Level Design for State Modeling / Formal Verification

**N/A — pure single-shot, single-connection probes with no concurrency invariants of our own.**

The only concurrency in scope is Nettacker's existing per-host thread pool ([nettacker/core/module.py:191-197](../nettacker/core/module.py#L191-L197)), which is already governed by `time_sleep_between_requests` and `thread_per_host` and is out of this runbook's scope. Per-probe state: `(host, port, group) → response` with no ordering dependency between probes. No durable state of our own (results land in the existing SQLite events table). No retries, queues, leases, or recovery protocol. `tla_required: false` (per [overview.md](slo/design/pqc-compliance-scanner-overview.md)).

---

## 6. Global Execution Rules

(Sections 6.1 — 6.11 from the v4 template apply verbatim. Notable project-specific reminders:)

- **6.1 Stay in scope**: this runbook touches `nettacker/modules/scan/pqc_scan.yaml`, `nettacker/core/lib/pqc.py`, `nettacker/core/module.py` (one-line `ignored_core_modules` edit), `tests/core/lib/test_pqc.py`, `tests/core/test_module_pqc.py`, `tests/e2e/test_pqc_scan_smoke.py`, `docs/Modules.md`. Anything else requires explicit milestone-level authorization.
- **6.4 Resource bounds**: 8 PQC TLS named-groups in v1, 4 SSH PQC algorithm strings — both bounded by code-reviewed tables, not config.
- **6.5 Static analysis**: `pre-commit run --all-files` per Nettacker's [AGENTS.md](../AGENTS.md).
- **6.7 No placeholders**: no `TODO` strings in production code; no `pass # implement later`.
- **6.10 Record evidence**: every Evidence Log row must be filled with the actual command output reference (e.g. `evidence/pqc-scanner-m1-baseline.txt`).
- **6.11 Test artifacts**: e2e tests against public hosts must be marked `@pytest.mark.e2e` and skipped in default `make test` if `NETTACKER_NO_NETWORK_TESTS=1`. No fixtures committed beyond hand-checked golden bytes.

---

## 7. Global Entry Rules / 8. Global Exit Rules

(Verbatim from v4 template.)

---

## 9. Background Context

### Current State

Nettacker is a Python 3.10–3.12 modular pen-test framework. Modules are YAML manifests in [nettacker/modules/](../nettacker/modules/) that reference Python "libraries" in [nettacker/core/lib/](../nettacker/core/lib/). The module loader at [nettacker/core/module.py:156-159](../nettacker/core/module.py#L156-L159) auto-discovers any `*.py` in `core/lib/` and binds it via `library.lower()` + `Library.capitalize() + Engine` naming. The closest existing prior art is [nettacker/core/lib/ssl.py](../nettacker/core/lib/ssl.py) with [nettacker/modules/scan/ssl_expiring_certificate.yaml](../nettacker/modules/scan/ssl_expiring_certificate.yaml). SSH support exists in [nettacker/core/lib/ssh.py](../nettacker/core/lib/ssh.py) but only for brute-force and uses paramiko's high-level `Transport`, which abstracts away the unilateral KEXINIT view we need for PQC enumeration.

### Problem

1. **No PQC posture visibility**. Nettacker reports SSL versions, weak ciphers, and certificate expiry, but not whether a server advertises ML-KEM / X25519MLKEM768 / mlkem768x25519-sha256 — the algorithms NIST FIPS 203 / IETF draft-ietf-tls-mlkem-07 / OpenSSH 9.9+ produce. This blocks the security-engineer use case of "scan our 800 endpoints and tell me % PQC-ready" that OMB M-23-02 (annual cryptographic inventory through 2035) and CNSA 2.0 (NSS new-acquisitions PQC by 2027-01-01) require an answer to.
2. **Existing TLS code path cannot probe PQC named groups**. CPython's stdlib `ssl` does not expose TLS 1.3 named-group selection; `ssl.set_ciphers()` operates on TLS 1.2 cipher strings. The existing `is_weak_cipher_suite()` in [ssl.py:59-107](../nettacker/core/lib/ssl.py#L59-L107) cannot be extended to enumerate PQC groups without raw ClientHello construction.
3. **Existing SSH code path cannot enumerate KEXINIT**. paramiko's `SSHClient.connect()` completes the handshake and returns the negotiated kex, not the server's full advertised list. The existing [ssh.py](../nettacker/core/lib/ssh.py) `SshLibrary` is brute-force-only.

### Target Architecture

See Section 3 diagram. Net additions: one YAML manifest, one Python library, one one-line edit to `module.py`, three test files, one docs update.

### Key Design Principles

1. **Light + reliable beats feature-rich**. One TCP connection per probe. RFC 8446 / RFC 4253 strict conformance. No handshake completion. No new system deps. Source: founder confirmation 2026-05-06; [synthesis.md §"Safety"](slo/research/pqc-compliance-scanner/synthesis.md).
2. **Verdict honesty**. `pqc_ready` only fires when at least one `status: standardized` algorithm is advertised. Drafts and experimentals appear in the advertised list but never trigger `pqc_ready`. Source: [security.md §6](slo/design/pqc-compliance-scanner-security.md).
3. **Operator escape hatch**. `pqc_no_active_probe=true` extra-arg disables the active TLS probe so passive SSH-side enumeration still works in known-fragile environments. Source: [security.md §4](slo/design/pqc-compliance-scanner-security.md).

### What to Keep

- All existing modules (`ssl_*`, `port_scan`, `subdomain_scan`, every `vuln/*`, every `brute/*`).
- The Nettacker module-loader auto-discovery convention at [module.py:69-74](../nettacker/core/module.py#L69-L74).
- Existing CLI flags, REST API surfaces, Web UI behavior.
- Existing SQLite schema. `SubmitLogsToDb()` is unchanged.
- Existing `paramiko` usage by `ssh.py` (brute-force code path).

### What to Change

- **`nettacker/core/module.py`** — add `"pqc_scan"` to the `ignored_core_modules` list. One-line edit, M1.
- **`nettacker/modules/scan/pqc_scan.yaml`** — NEW manifest. M1 ships SSH step only; M2 adds TLS step (per critique F-ENG-2).
- **`nettacker/core/lib/pqc.py`** — NEW library + engine + algorithm tables. M1 ships skeleton + SSH probe; M2 adds TLS probe; M3 finalizes verdict + opt-out.
- **`docs/slo/design/pqc-compliance-scanner-interfaces.md`** — add IETF-pinned key_share length table at M2 pre-flight (per critique F-ENG-3).
- **`docs/Modules.md`** — add user-facing entry for `pqc_scan`. M3.

### Global Red Lines

- No new pip dependencies anywhere in v1.
- No edits to existing modules' YAML or library files.
- No changes to the SQLite schema.
- No CLI flag rename or removal.
- No edits to `nettacker/web/` (Web UI auto-discovers modules from the YAML directory).
- No retries inside the library — each probe is single-shot. **Library MUST catch every recoverable network exception** (`socket.timeout`, `socket.error`, `ConnectionRefusedError`, `ConnectionResetError`, `OSError`) and convert it to a `verdict=unknown` + `errors=[…]` dict — so [BaseEngine.run() at base.py:288-293](../nettacker/core/lib/base.py#L288-L293) never retries probe failures. The framework-level `retries` knob then only re-runs true library bugs (e.g., `AttributeError`), which we never want to mask anyway. (Critique F-ENG-1 + threat-model abuse-3.)
- No background threads or async code in the library beyond what stdlib `socket` requires.
- No mock objects committed to production paths.

---

## 10. Carry-forward from prior retros

(No prior retros for this runbook prefix yet. Section reserved.)

| Issue | Title | Suggested lane | Suggested milestone | Status |
|---|---|---|---|---|
| _none_ | | | | |

---

## 11. BDD and Runtime Validation Rules

(Verbatim from v4 template. Project-specific test naming:)

| Layer | Convention | Location |
|---|---|---|
| Library unit tests | `test_<symbol>` functions in `test_pqc.py` | `tests/core/lib/test_pqc.py` |
| Module-level integration tests | `test_pqc_scan_<scenario>` | `tests/core/test_module_pqc.py` |
| E2E runtime smoke | `test_smoke_<target>` | `tests/e2e/test_pqc_scan_smoke.py` (marked `@pytest.mark.e2e`) |
| Golden-byte fixtures | hex strings inline in test source; never committed as binary | `tests/core/lib/test_pqc.py` |

---

## 12. Dependency, Migration, and Refactor Policy

- **Dependency policy**: NO new deps in any milestone of v1. The stack-decision doc forbids it. If a milestone discovers a hard need, STOP and re-open the stack decision.
- **Migration policy**: NO schema migrations. Results write to existing event columns.
- **Refactor budget**: every milestone is `Minimal local refactor permitted in listed files only`. The one-line `ignored_core_modules` edit in M1 is explicitly authorized.

---

## 13. Evidence Log Template

(Verbatim from v4 template.)

---

## 14. Self-Review Gate

(Verbatim from v4 template.)

---

## 15. Lessons-Learned File Template

Path: `docs/slo/lessons/pqc-scanner-m<N>.md` (verbatim shape from v4 template).

---

## 16. Completion Summary Template

Path: `docs/slo/completion/pqc-scanner-m<N>.md` (verbatim shape from v4 template).

---

## 17. Milestone Plan

### Milestone 1 — Foundation + SSH passive PQC probe

**Goal**: Ship a runnable `nettacker -m pqc_scan -i <ssh_host>` command that opens one TCP connection to the SSH port, reads the server's MSG_KEXINIT packet, and reports whether the server advertises any of the PQC SSH KEX algorithms (`mlkem768x25519-sha256`, `sntrup761x25519-sha512@openssh.com`). No TLS path yet — that is M2. SSH first because it is strictly passive (server unilaterally advertises KEXINIT before negotiation per RFC 4253 §7.1) and therefore the safest path to land first.

**Context**: Nettacker has no PQC scanning today. We start with the lowest-blast-radius probe (passive SSH KEXINIT enumeration) so the framework wiring and algorithm-table machinery exists before we introduce the higher-risk active TLS ClientHello probe in M2. The new library file is auto-discovered by [nettacker/core/module.py:69-74](../nettacker/core/module.py#L69-L74); the one-line edit to `ignored_core_modules` lets the module run without first running `port_scan`, matching the existing `ssl_*` pattern at [module.py:48-58](../nettacker/core/module.py#L48-L58).

**Carmack-style reliability goal**: Bounded resources (single TCP connection per (host, port); banner read capped at 255 bytes per RFC 4253 §4.2; KEXINIT read capped at 35,000 bytes per RFC 4253 §6) + invalid states unrepresentable (Verdict and ProbeResult typed; algorithm-table entries TypedDict).

**Important design rule**: Read raw bytes from the socket; do NOT instantiate a paramiko `Transport`. paramiko abstracts away the advertisement view we need. We re-use `paramiko.util` only as a reference for SSH wire format if useful — but the live path is `socket` + `struct`.

**Refactor budget**: `Minimal local refactor permitted in listed files only`. The one-line edit to `nettacker/core/module.py` is explicitly authorized.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | CLI: `nettacker -m pqc_scan -i <host>` (host is hostname or IP). Optional: `--ports 22,2222 --excluded-ports <list>`. |
| Outputs | Per-target log entry (existing log path). Response dict with fields `host`, `port`, `service="ssh"`, `scan_succeeded`, `verdict` (M3 finalizes; M1 returns provisional verdict computed from advertised lists), `ssh_pqc_kex_advertised`, `ssh_classical_kex_advertised`, `ssh_server_banner`, `errors`, `duration_ms`. SQLite row in existing events table. |
| Interfaces touched | NEW: `library: pqc`, method `ssh_pqc_scan`, classes `PqcLibrary`/`PqcEngine`. CHANGED: `nettacker/core/module.py` `ignored_core_modules` list. |
| Files allowed to change | `nettacker/core/lib/pqc.py` (NEW), `nettacker/modules/scan/pqc_scan.yaml` (NEW), `nettacker/core/module.py` (one-line edit only — add `"pqc_scan"` to `ignored_core_modules`), `tests/core/lib/test_pqc.py` (NEW), `tests/core/test_module_pqc.py` (NEW), `.gitignore` if needed. |
| Files to read before changing anything | [nettacker/core/lib/base.py](../nettacker/core/lib/base.py), [nettacker/core/lib/ssl.py](../nettacker/core/lib/ssl.py), [nettacker/core/lib/ssh.py](../nettacker/core/lib/ssh.py), [nettacker/core/module.py](../nettacker/core/module.py), [nettacker/modules/scan/ssl_expiring_certificate.yaml](../nettacker/modules/scan/ssl_expiring_certificate.yaml), [tests/core/lib/test_ssl.py](../tests/core/lib/test_ssl.py). |
| New files allowed | `nettacker/core/lib/pqc.py`, `nettacker/modules/scan/pqc_scan.yaml`, `tests/core/lib/test_pqc.py`, `tests/core/test_module_pqc.py`. |
| New dependencies allowed | `none`. |
| Migration allowed | `no`. |
| Compatibility commitments | Every existing module continues to function. `make test` baseline stays green. The `ssh.py` `SshLibrary.brute_force` path is untouched. The Web UI auto-discovers the new module without code changes. |
| Resource bounds introduced/changed | (a) ≤4 SSH PQC algorithm strings in `SSH_PQC_KEX_ALGORITHMS` table (hard cap); (b) banner read ≤255 bytes; (c) KEXINIT packet read ≤35,000 bytes; (d) one TCP connection per (host, port); (e) FD count delta is zero across every probe code path (success and failure). |
| Invariants/assertions required | (a) `assert len(SSH_PQC_KEX_ALGORITHMS) <= 4`; (b) every table entry has keys `kind`, `status`, `since_openssh_version`; (c) `ProbeResult` discriminated by tag string in `{"kexinit_received","banner_only","timeout","tcp_closed"}`; (d) `Verdict` strictly in the four-value enum; (e) **library catches every recoverable network exception** so `BaseEngine.run()` retry loop is a no-op for probe failures (critique F-ENG-1); (f) **server-controlled SSH name-list strings are validated** against `^[A-Za-z0-9._@+/-]+$` per RFC 4250 §6 at parse boundary; non-conformant strings are dropped with an entry in `errors` (critique F-SEC-1, CWE-117); (g) FD count delta is zero across every probe (critique F-SEC-3, CWE-404). |
| Debugger / inspection expectation | At least one test must be runnable under `pytest --pdb` (i.e., produces a controlled failure for inspection). Lessons file records one debugger session. |
| Static analysis gates | `poetry run ruff format` + `poetry run ruff check` clean on all changed files. `pre-commit run --all-files` clean. |
| Forbidden shortcuts | No paramiko `Transport`. No real network calls in unit tests (use a `socket.socketserver`-based fake that replays canned bytes). No `time.sleep` in production code. No swallowed `socket.error` — every failure is recorded in `errors`. No `# TODO`. **No log emission of unsanitized server-controlled bytes** (F-SEC-1). |
| Data classification | Internal (network reachability + advertised algorithm lists; no credentials, no personal data). |
| Proactive controls in play | OWASP Proactive Controls C2 (input validation — strict KEXINIT parse), C5 (secure-by-default — no handshake completion), C9 (security logging — every probe logged via existing `process_conditions`). |
| Abuse acceptance scenarios | `tm-pqc-compliance-scanner-abuse-4` (oversized banner — capped at 255 bytes) and `tm-pqc-compliance-scanner-abuse-5` (transparent banner — documented as intentional choice) and `tm-pqc-compliance-scanner-abuse-6` (resource exhaustion — `timeout` enforced). All three covered in BDD scenarios below. |

#### Out of Scope / Must Not Do

- TLS active probe (M2).
- Verdict-with-compliance-notes wording (M3).
- `pqc_no_active_probe` opt-out wiring (M3 — for v1 of M1, the active path simply does not exist yet).
- Editing any existing YAML manifest.
- Editing the Web UI.
- Adding any pip dependency.

#### Pre-Flight

1. Run Global Entry Protocol §7.
2. No prior lessons file (this is M1).
3. Read the files in "Files to read before changing anything".
4. Copy Evidence Log into working notes.
5. Run `make test` and confirm baseline green; record output to `evidence/pqc-scanner-m1-baseline.txt`.
6. **Verify Web UI module-discovery mechanism** (critique F-ENG-4): read [nettacker/web/](../nettacker/web/) and `nettacker/api/` for the source of the Web UI module list. If the Web UI maintains a separate manifest (JSON / static asset / hardcoded list) rather than auto-discovering YAMLs, add that file to M3's allow-list and document the finding in M1's Evidence Log. If auto-discovery is confirmed, document that confirmation in the Evidence Log.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `nettacker/core/lib/pqc.py` | NEW: module-level constants `TLS_PQC_NAMED_GROUPS` (table only — actual TLS probe lands in M2), `SSH_PQC_KEX_ALGORITHMS`; classes `PqcLibrary` (with `ssh_pqc_scan` method only in M1) and `PqcEngine` (skeleton). **Per critique F-ENG-2, no `tls_pqc_scan` stub in M1** — that method is added in M2 alongside the YAML edit that references it. |
| `nettacker/modules/scan/pqc_scan.yaml` | NEW: manifest with `info`, `payloads[0].library: pqc`, **one payload `step` for `ssh_pqc_scan`** (default ports 22, 2222) only. The TLS step is added in M2. |
| `nettacker/core/module.py` | One-line edit: add `"pqc_scan"` to `ignored_core_modules` at the existing list (line ~48–58). |
| `tests/core/lib/test_pqc.py` | NEW: unit tests for `SSH_PQC_KEX_ALGORITHMS` table well-formedness, `_parse_ssh_kexinit()` helper, `_send_ssh_banner()` helper, `ssh_pqc_scan()` end-to-end against a fake socket server. |
| `tests/core/test_module_pqc.py` | NEW: integration test that loads `pqc_scan.yaml` via TemplateLoader, instantiates `PqcEngine`, and verifies a fake SSH server (bound to 127.0.0.1 on a random port) is correctly probed and produces a populated response dict. |
| `.gitignore` | Add `evidence/` if not present (we write evidence-log artifacts there during execution but do not commit them). |

#### Step-by-Step

1. Write BDD test stubs in `tests/core/lib/test_pqc.py` for every scenario in the BDD table below; confirm they fail.
2. Write the integration test in `tests/core/test_module_pqc.py`; confirm it fails.
3. Implement `SSH_PQC_KEX_ALGORITHMS` table with the 2 OpenSSH-shipped algorithms + 2 reserved slots (table cap = 4).
4. Implement the SSH probe: open TCP, send `SSH-2.0-Nettacker_PQC_Scan\r\n`, read banner (cap 255 bytes), read first packet (length-prefixed, cap 35000 bytes), parse MSG_KEXINIT (`uint8 type=20`, 16 bytes cookie, 10 name-list strings), extract `kex_algorithms` name-list, **validate every name string against `^[A-Za-z0-9._@+/-]+$` (RFC 4250 §6) at the parse boundary; drop non-conformant strings into `errors`** (F-SEC-1, CWE-117), classify each conforming entry against the table, close socket.
5. Implement `_parse_ssh_kexinit()` helper as a pure function over `bytes → dict` for test isolation. Wrap every `socket.*` exception in `tls_pqc_scan`/`ssh_pqc_scan` outer-try so the framework retry loop never sees an `Exception` (F-ENG-1).
6. Implement the YAML manifest with the SSH step only.
7. One-line edit to `nettacker/core/module.py` adding `"pqc_scan"` to `ignored_core_modules`.
8. Run `pre-commit run --all-files`, `make test`, `poetry run nettacker -m pqc_scan -i <local fake SSH server>` smoke.
9. Verify Evidence Log rows including FD-leak check and "library never raises" check.

#### BDD Acceptance Scenarios

**Feature: SSH PQC posture probe**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Server advertises mlkem768x25519-sha256 | happy path | local fake SSH server replays a canned KEXINIT containing `mlkem768x25519-sha256` in `kex_algorithms` | `ssh_pqc_scan(host, port, timeout=5)` runs | response `verdict="pqc_ready"`, `ssh_pqc_kex_advertised == ["mlkem768x25519-sha256"]`, `errors == []` |
| Server advertises only classical KEX | happy path | server replays KEXINIT with only `curve25519-sha256`, `ecdh-sha2-nistp256` | probe runs | `verdict="classical_only"`, `ssh_pqc_kex_advertised == []`, `ssh_classical_kex_advertised` populated |
| Server advertises sntrup761x25519 hybrid only | happy path | server replays KEXINIT with `sntrup761x25519-sha512@openssh.com` only | probe runs | `verdict="hybrid_only"`, `ssh_pqc_kex_advertised == ["sntrup761x25519-sha512@openssh.com"]` |
| TCP refused | invalid input | port 22 closed on target | probe runs | `verdict="unknown"`, `scan_succeeded=False`, `errors == ["tcp_refused"]` |
| Banner timeout | dependency failure | server accepts TCP but never sends banner | probe runs | `verdict="unknown"`, `errors == ["banner_timeout"]`, no thread leak (verified via test fixture sentinel) |
| Oversized banner | resource bound (abuse-4) | server sends 1MB banner | probe runs | exception caught, `errors == ["banner_overflow_capped_at_255"]`, socket closed cleanly |
| Oversized KEXINIT | resource bound | server sends 100KB KEXINIT packet | probe runs | `errors == ["kexinit_overflow_capped_at_35000"]`, socket closed |
| Server sends garbage | invalid input | server sends random bytes for banner | probe runs | `verdict="unknown"`, `errors == ["malformed_banner"]` |
| Server advertises malformed algorithm name (`tm-pqc-compliance-scanner-abuse-5` variant; CWE-117 mitigation) | abuse case | mock server's KEXINIT contains `mlkem768x25519-sha256\n[CRITICAL]forged log line` in `kex_algorithms` | probe runs | malformed name dropped at parse boundary; `errors` includes `"malformed_algorithm_name_<hex_prefix>"`; advertised list contains only RFC-conformant strings; logged event contains no newlines from server |
| FD leak prevention (CWE-404) | resource bound | snapshot `psutil.Process().num_fds()` before probe | run probe (success or failure path) | post-probe FD count == pre-probe FD count |
| Library never raises into framework retry loop (F-ENG-1) | resource bound | force `socket.timeout` via mock server | run via `BaseEngine.run()` with `options['retries']=3` | library returns dict on first call; framework does NOT re-call (verified by mock-server connection counter == 1, not 3) |
| Algorithm-table well-formed | assertion violation | unit test of table | iterate entries | every entry has required keys; len ≤ 4 |
| Existing modules still work | compatibility | full `make test` | runs | existing test suite green |

#### Regression Tests

- Full `make test` — all existing tests pass.
- `tests/core/lib/test_ssl.py` — every existing case still passes.
- `tests/core/test_module.py` — module loader still discovers existing modules.
- Manual: `poetry run nettacker -m ssl_expiring_certificate_scan -i example.com` still works.

#### Compatibility Checklist

- [ ] `nettacker -m ssl_expiring_certificate_scan -i <host>` still works.
- [ ] `nettacker -m port_scan -i <host>` still works.
- [ ] Web UI lists `pqc_scan` as a discoverable module without code changes.
- [ ] Existing SQLite events table accepts new module's logs without migration.

#### E2E Runtime Validation

**File**: `tests/core/test_module_pqc.py`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_pqc_scan_module_loads_and_runs_against_fake_ssh` | YAML → engine → library wiring works end-to-end with a localhost fake SSH server. | response dict contains `verdict`, `ssh_pqc_kex_advertised`, and DB log row created. |
| `test_pqc_scan_module_in_ignored_core_modules` | The one-line `module.py` edit took effect. | `Module(...)` constructed without prior `port_scan` results does not skip the pqc_scan payload. |

#### Smoke Tests

- [ ] `poetry run nettacker -m pqc_scan -i 127.0.0.1 --ports <fake-ssh-port>` against a local fake server prints a success event.
- [ ] `poetry run nettacker --help` lists `pqc_scan` in the modules section (auto-discovery sanity check).
- [ ] `pre-commit run --all-files` passes.
- [ ] `make test` passes.
- [ ] `git status` shows no untracked test artifacts.

#### Evidence Log

(Filled at execution time per §13 template.)

#### Definition of Done

- All BDD scenarios above pass.
- E2E test `test_pqc_scan_module_loads_and_runs_against_fake_ssh` passes.
- `make test` baseline still green (no regressions).
- `pre-commit run --all-files` clean.
- Resource bounds verified by tests.
- Algorithm-table assertion `len(SSH_PQC_KEX_ALGORITHMS) <= 4` holds and is asserted in code.
- One debugger session recorded in lessons file.
- `docs/slo/lessons/pqc-scanner-m1.md` written.
- `docs/slo/completion/pqc-scanner-m1.md` written.
- Milestone Tracker updated.

#### Post-Flight

- **ARCHITECTURE.md**: N/A (we keep our scope-doc at `docs/slo/design/pqc-compliance-scanner-architecture.md`; no edit to a top-level ARCHITECTURE.md because none exists).
- **README.md**: no edit yet — wait for M3 when CLI surface is complete.
- **`docs/Modules.md`**: no edit yet — M3.
- **Other docs**: lessons + completion files only.

#### Notes

- We deliberately ship the YAML referencing `tls_pqc_scan` from M1 even though the method is a stub, so the manifest does not need to change in M2 (only the library implementation does). This keeps the YAML file's stable-interface promise.

---

### Milestone 2 — TLS 1.3 active PQC ClientHello probe

**Goal**: Implement `PqcLibrary.tls_pqc_scan(host, port, timeout)` so it sends one strict-RFC-8446 TLS 1.3 ClientHello per PQC named group in `TLS_PQC_NAMED_GROUPS` (≤8 codepoints in v1) and classifies each response (ServerHello-with-this-group / HelloRetryRequest / handshake_failure Alert / timeout / TCP-closed). The method returns a populated `tls_pqc_groups_advertised` list and provisional verdict; M3 finalizes verdict + opt-out + compliance notes.

**Context**: Stdlib `ssl` cannot probe TLS 1.3 named groups, so we hand-build the ClientHello bytes per RFC 8446 §4.1.2. The risk surface (per `tm-pqc-compliance-scanner-abuse-1` and `abuse-2`) is real and the mitigation is golden-byte fixtures + single-record-read invariant.

**Carmack-style reliability goal**: Make invalid states unrepresentable (typed `ProbeResult` tagged union); bounded resources (≤8 connections per (host, port); ≤16,384 bytes per record); inspect state, do not guess (golden-byte fixtures + wireshark validation in lessons).

**Important design rule**: The ClientHello must round-trip through hand-checked fixtures. If the byte output for a known named-group differs from the recorded fixture by even one byte, M2 is not done.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | (host, port, timeout) from existing YAML step. Per-call: a sequence of named-group probes determined by `TLS_PQC_NAMED_GROUPS`. |
| Outputs | `tls_pqc_groups_advertised`, `tls_pqc_groups_probed`, `tls_classical_groups_advertised` (extracted from any received ServerHello extension when present), `errors`, `duration_ms`, `service="tls"`. |
| Interfaces touched | `PqcLibrary.tls_pqc_scan(host, port, timeout) -> dict`. The stub from M1 is replaced with the real implementation. YAML manifest unchanged. |
| Files allowed to change | `nettacker/core/lib/pqc.py` (add `tls_pqc_scan` method + helpers `_build_tls13_client_hello`, `_parse_tls13_server_response`, `TLS_PQC_NAMED_GROUPS` table fully populated), **`nettacker/modules/scan/pqc_scan.yaml` (add the TLS step that M1 deferred — critique F-ENG-2)**, `tests/core/lib/test_pqc.py` (TLS scenarios + golden bytes + parser fuzz/torture test), `tests/core/test_module_pqc.py` (TLS integration scenario), **`docs/slo/design/pqc-compliance-scanner-interfaces.md`** (add the IETF-pinned key_share length table — critique F-ENG-3, may already be added in pre-flight). |
| Files to read before changing anything | `nettacker/core/lib/pqc.py` as it stands at end of M1, RFC 8446 §4.1.2 (for ClientHello shape — read offline reference; cite IANA codepoints from interfaces.md), [docs/slo/design/pqc-compliance-scanner-interfaces.md](slo/design/pqc-compliance-scanner-interfaces.md). |
| New files allowed | `none`. |
| New dependencies allowed | `none`. |
| Migration allowed | `no`. |
| Compatibility commitments | M1's SSH path continues to work. Stub `tls_pqc_scan` from M1 is REPLACED, not removed — the YAML reference is unchanged. `make test` stays green. |
| Resource bounds introduced/changed | (a) `len(TLS_PQC_NAMED_GROUPS) <= 8` asserted; (b) one TCP connection per (host, port, group); (c) `recv()` per probe ≤ 16,384 bytes (one TLS record); (d) probe loop exits on first received `handshake_failure` alert (we do not retry the same group); (e) FD count delta is zero across every probe code path (F-SEC-3, CWE-404). |
| Invariants/assertions required | (a) `assert len(TLS_PQC_NAMED_GROUPS) <= 8`; (b) every IANA codepoint in the table is in valid TLS NamedGroup numeric range; (c) emitted ClientHello length is ≤ 1500 bytes (paranoid cap to prevent accidental record fragmentation — must accommodate the 1216-byte X25519MLKEM768 key_share + extensions overhead); (d) `ProbeResponse` is a tagged union as per §4.5; (e) `_parse_tls13_server_response()` is total — every `bytes` input maps to a tagged result; **no exception ever escapes** (F-SEC-2, CWE-787 / CWE-770); (f) `_build_tls13_client_hello()` uses key_share lengths from the IETF-pinned table in interfaces.md (F-ENG-3); (g) outer `tls_pqc_scan` catches every recoverable network exception so the framework retry loop is a no-op (F-ENG-1). |
| Debugger / inspection expectation | At least one ClientHello byte sequence inspected via `wireshark` against a local mock TLS server during development; documented in lessons file. |
| Static analysis gates | Same as M1: ruff format + ruff check + pre-commit. |
| Forbidden shortcuts | No use of stdlib `ssl.SSLContext.wrap_socket()` for the probe — we construct bytes ourselves. No completing a handshake. No more than one record read per probe. No fragmented records emitted. No retries on the same group. No silent fallback when a server sends an unexpected response (record raw bytes in `errors`, do not invent classification). |
| Data classification | Internal. |
| Proactive controls in play | C2 (input validation — strict TLS record parse), C5 (secure-by-default — single-record-read invariant), C9 (security logging — every probe logged). |
| Abuse acceptance scenarios | `tm-pqc-compliance-scanner-abuse-1` (fragile-LB target — covered by single-conn-per-group invariant; note in lessons that a true mitigation requires the M3 opt-out), `tm-pqc-compliance-scanner-abuse-2` (oversized ServerHello — `recv()` capped at 16,384). |

#### Out of Scope / Must Not Do

- The `pqc_no_active_probe` opt-out wiring (M3).
- Final verdict + compliance-notes string formatting (M3).
- TLS 1.2 fallback probing (out of v1 scope; pure PQC is TLS 1.3+).
- DTLS, QUIC, SMTP STARTTLS, etc. (TCP TLS 1.3 only in v1).
- Cert-chain PQC analysis (v2).

#### Pre-Flight

1. Global Entry Protocol §7.
2. Read `docs/slo/lessons/pqc-scanner-m1.md` and apply rules.
3. Re-read M1's `pqc.py` to understand existing helpers.
4. Confirm `make test` green from M1.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `nettacker/core/lib/pqc.py` | Replace stub `tls_pqc_scan` with real implementation; add `_build_tls13_client_hello(group_codepoint, sni_host)`; add `_parse_tls13_server_response(bytes)`; finalize `TLS_PQC_NAMED_GROUPS` table with all 8 codepoints. |
| `tests/core/lib/test_pqc.py` | Add TLS scenarios (see BDD below). Add golden-byte fixtures: hand-checked hex strings for ClientHello of `X25519MLKEM768`, `MLKEM768`, and one classical group as control. |
| `tests/core/test_module_pqc.py` | Add integration scenario with localhost mock TLS server replaying canned ServerHello bytes. |

#### Step-by-Step

1. Write BDD tests + golden-byte fixtures first.
2. Confirm tests fail.
3. Implement `_build_tls13_client_hello()` per RFC 8446 §4.1.2 — record layer header + handshake header + ClientHello body (legacy_version=0x0303, random=32 random bytes, legacy_session_id=32 bytes, cipher_suites=[0x1301 TLS_AES_128_GCM_SHA256, 0x1302 TLS_AES_256_GCM_SHA384, 0x1303 TLS_CHACHA20_POLY1305_SHA256], compression_methods=[0], extensions=[supported_versions=0x0304, supported_groups=[group_codepoint], key_share=[group_codepoint, dummy_public_key_of_correct_length], server_name=sni_host, signature_algorithms=[0x0403 ecdsa_secp256r1_sha256, 0x0804 rsa_pss_rsae_sha256, 0x0807 ed25519]]).
4. **Critical**: dummy public-key bytes for PQC groups must be of the correct length per the IETF draft (e.g., `X25519MLKEM768` = 32 + 1184 = 1216 bytes). Otherwise the server sends `decode_error` alert instead of either `handshake_failure` or a ServerHello, and we mis-classify. Use the lengths documented in `draft-ietf-tls-ecdhe-mlkem-04` and `draft-ietf-tls-mlkem-07`.
5. Implement `_parse_tls13_server_response()` — read TLS record header (5 bytes: type, version, length), branch on type=22 (handshake) → ServerHello / HelloRetryRequest, type=21 (alert) → level + description.
6. Validate emitted bytes against golden fixtures.
7. **Wireshark loop**: spin a local mock TLS server (`socket` in a thread, accept-and-print), send one ClientHello, capture pcap, inspect in wireshark, confirm shape is recognized as a clean TLS 1.3 ClientHello. Document in lessons.
8. Run static analysis + tests.

#### BDD Acceptance Scenarios

**Feature: TLS 1.3 PQC ClientHello probe**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| ClientHello bytes match golden fixture for X25519MLKEM768 | happy path | hand-checked hex fixture for codepoint 0x11ec | `_build_tls13_client_hello(0x11ec, "example.com")` | output bytes == fixture |
| ClientHello bytes match golden fixture for MLKEM768 | happy path | hand-checked fixture for 0x0201 | `_build_tls13_client_hello(0x0201, "example.com")` | bytes == fixture |
| Server selects probed PQC group | happy path | mock server replays ServerHello with selected_group=0x11ec | `tls_pqc_scan(host, port)` runs | `tls_pqc_groups_advertised` includes "X25519MLKEM768" |
| Server sends HelloRetryRequest (group supported but not preferred) | happy path | mock server replays HRR specifying X25519MLKEM768 | probe runs | group counted as "supported" — added to advertised list |
| Server sends handshake_failure alert | invalid input | mock server returns alert(level=2, description=40) | probe runs | group NOT added to advertised list; entry in `errors` is empty (this is a *normal* "not supported" response) |
| Server sends decode_error alert | invalid input | mock server returns alert(level=2, description=50) | probe runs | group NOT advertised; `errors` records `"decode_error_for_<group>"` because this hints our ClientHello bytes are wrong |
| Server times out after ClientHello | dependency failure | mock server accepts but never replies | probe runs | group NOT advertised; `errors` records `"timeout_<group>"` |
| TCP refused on TLS port | dependency failure | local listener absent | probe runs | `scan_succeeded=False`, `errors=["tcp_refused"]`, no per-group rows |
| Server sends oversized record (`tm-pqc-compliance-scanner-abuse-2`) | resource bound | mock server replays 1MB after handshake header | probe runs | only 16,384 bytes consumed; socket closed; group recorded as "ambiguous_oversized_response" |
| Probe completes ≤8 connections per (host, port) | resource bound | full table | probe runs against mock | exactly `len(TLS_PQC_NAMED_GROUPS)` TCP connects observed |
| FD leak prevention (CWE-404) | resource bound | snapshot `psutil.Process().num_fds()` before TLS probe loop | run probe (success or failure) | post-probe FD count == pre-probe FD count |
| Library never raises into framework retry loop (F-ENG-1) | resource bound | force `socket.timeout` mid-probe via mock | call via `BaseEngine.run()` with `options['retries']=3` | mock-server connection counter == 1, not 3 |
| Parser is total — torture test (F-SEC-2, CWE-787/770) | abuse case | seeded RNG generates 100 mutations of a valid ServerHello byte string | feed each to `_parse_tls13_server_response` | no exception escapes any call; every output is a tagged result OR an `errors` entry |
| Algorithm-table well-formed | assertion violation | unit test | iterate `TLS_PQC_NAMED_GROUPS` | every entry valid; `len <= 8`; no duplicate codepoints; **every entry's `key_share_bytes` field matches the IETF-pinned table in interfaces.md** (F-ENG-3) |
| Existing tests still pass | compatibility | full suite | `make test` | green |

#### Regression Tests

- Full `make test`.
- M1 SSH BDD scenarios still pass.
- `nettacker -m ssl_expiring_certificate_scan -i example.com` still works.

#### Compatibility Checklist

- [ ] M1 SSH probe still works.
- [ ] No new pip dep introduced.
- [ ] Web UI auto-discovery still works.
- [ ] Existing modules untouched.

#### E2E Runtime Validation

**File**: `tests/core/test_module_pqc.py`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_tls_pqc_scan_against_local_mock_server` | TLS probe against a localhost mock server returns a populated `tls_pqc_groups_advertised`. | At least one group in the list when the mock advertises; empty list when the mock alerts. |
| `test_clienthello_byte_for_byte_matches_fixture` | Hand-checked golden fixture is regenerated identically. | byte equality |

#### Smoke Tests

- [ ] `poetry run nettacker -m pqc_scan -i 127.0.0.1 --ports <mock-tls-port>` exercises the TLS path end-to-end.
- [ ] `pre-commit run --all-files` passes.
- [ ] `make test` passes.
- [ ] Wireshark capture confirms ClientHello shape matches RFC 8446.

#### Evidence Log

(Filled per §13 template.)

#### Definition of Done

- All BDD scenarios pass.
- Golden-byte fixtures match emitted bytes for at least 3 named groups (`X25519MLKEM768`, `MLKEM768`, one classical control e.g. `x25519`).
- `make test` baseline green.
- `pre-commit run --all-files` clean.
- Wireshark inspection documented in lessons.
- `docs/slo/lessons/pqc-scanner-m2.md` written.
- `docs/slo/completion/pqc-scanner-m2.md` written.

#### Post-Flight

- **README.md**: no edit yet.
- **`docs/Modules.md`**: no edit yet (M3).
- **Other docs**: lessons + completion.

#### Notes

- The v1 table now includes `mlkem1024` (0x0202) and `SecP384r1MLKEM1024` (per critique F-CEO-1) so the M3 verdict can honestly map to **CNSA 2.0** which mandates ML-KEM-1024 for NSS by 2027-01-01. `mlkem512` remains excluded — no compliance framework requires it and OpenSSL 3.5 / browsers / Cloudflare deployments as of 2026-05 standardize on the 768/1024 tier. The 8-codepoint cap is now: `MLKEM768`, `MLKEM1024`, `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, plus 3 reserved slots (`MLKEM512` deliberately omitted; future X-Wing or other hybrids land in reserved slots).

---

### Milestone 3 — Verdict, opt-out, docs, end-to-end smoke

**Goal**: Wire the final verdict logic in `PqcEngine.apply_extra_data()`, implement the `pqc_no_active_probe` per-module extra-arg opt-out, write user-facing docs in `docs/Modules.md`, and run end-to-end CLI smoke against at least one real public TLS endpoint known to advertise PQC and at least one real public SSH endpoint known to advertise PQC. Optionally update `README.md` Key Features list.

**Context**: M1 + M2 ship the probe machinery. M3 is the polish + safety + visibility milestone that makes the feature usable in the wild.

**Carmack-style reliability goal**: No silent failure (verdict + compliance_notes are human-readable; opt-out is honored visibly via a structured log line); preserve compatibility (no edits to existing modules).

**Important design rule**: `verdict="pqc_ready"` MUST require at least one `status: standardized` algorithm advertised — drafts and experimentals never trigger it. The `compliance_notes` field is the audit-trail string.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | M1 + M2 outputs. CLI: `nettacker -m pqc_scan -i <host> --modules-extra-args pqc_no_active_probe=true`. |
| Outputs | Full response shape per [interfaces.md](slo/design/pqc-compliance-scanner-interfaces.md): `verdict` + `compliance_notes`. New: `docs/Modules.md` section. Optional: `README.md` Key Features bullet. |
| Interfaces touched | `PqcEngine.apply_extra_data()` final form; `pqc_no_active_probe` extra-arg honored. |
| Files allowed to change | `nettacker/core/lib/pqc.py` (verdict logic + opt-out branch), `nettacker/modules/scan/pqc_scan.yaml` (response conditions referencing `verdict`), `tests/core/lib/test_pqc.py` (verdict scenarios), `tests/e2e/test_pqc_scan_smoke.py` (NEW), `docs/Modules.md` (NEW section), `README.md` (optional one-line bullet). |
| Files to read before changing anything | M1 + M2 final code, [docs/Modules.md](Modules.md) existing entries, [README.md](../README.md) Key Features list. |
| New files allowed | `tests/e2e/test_pqc_scan_smoke.py`. |
| New dependencies allowed | `none`. |
| Migration allowed | `no`. |
| Compatibility commitments | M1 + M2 BDD all still pass. Existing modules untouched. CLI smoke does not flake. |
| Resource bounds introduced/changed | None new. (Opt-out reduces probe count from `≤8 + 1 SSH` to `1 SSH` only.) |
| Invariants/assertions required | (a) `verdict in {"pqc_ready","hybrid_only","classical_only","unknown"}`; (b) `verdict="pqc_ready"` ⇒ ≥1 advertised algorithm has `status="standardized"`; (c) when `pqc_no_active_probe=true`, `tls_pqc_scan()` returns immediately with `errors=["active_probe_disabled_by_operator"]` and the SSH probe still runs. |
| Debugger / inspection expectation | At least one `pdb` step through verdict logic for the `hybrid_only` boundary case. |
| Static analysis gates | Same. |
| Forbidden shortcuts | No `verdict="pqc_ready"` based on draft/experimental status. No removing or renaming any verdict value. No skipping the e2e smoke just because the CI doesn't have outbound network — mark it `@pytest.mark.e2e` and skip when `NETTACKER_NO_NETWORK_TESTS=1`. |
| Data classification | Internal. |
| Proactive controls in play | C5 (secure-by-default — opt-out is opt-in to disable, not opt-out to enable), C9 (security logging — opt-out logged as a structured event). |
| Abuse acceptance scenarios | `tm-pqc-compliance-scanner-abuse-1` (fragile-LB — opt-out is the documented mitigation, completing the chain started in M2), `tm-pqc-compliance-scanner-abuse-3` (CI fanout — docs explicitly recommend conservative `time_sleep_between_requests`). |

#### Out of Scope / Must Not Do

- v2 features (cert-chain PQC, SSH host-key PQC, `mlkem512` / `mlkem1024`).
- Any rename of the verdict enum or response field names.
- Adding a Web UI panel (auto-discovery is sufficient).
- Editing any existing module.

#### Pre-Flight

1. Global Entry Protocol §7.
2. Read M1 + M2 lessons.
3. Confirm baseline `make test` green.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `nettacker/core/lib/pqc.py` | Final `PqcEngine.apply_extra_data()` with verdict logic + `compliance_notes` string. Opt-out branch in `tls_pqc_scan()` early-returns when `pqc_no_active_probe=true`. |
| `nettacker/modules/scan/pqc_scan.yaml` | Response conditions reference `verdict` field for matching. |
| `tests/core/lib/test_pqc.py` | Verdict scenarios + opt-out scenario. |
| `tests/e2e/test_pqc_scan_smoke.py` | NEW. End-to-end CLI smoke against `tls13.1d.pw` (PQC-ready test endpoint) and `github.com:22` (sntrup761x25519 advertised). Marked `@pytest.mark.e2e`. |
| `docs/Modules.md` | NEW section "PQC Compliance Scanner (`pqc_scan`)" with usage examples + verdict semantics + opt-out flag + safety note. |
| `README.md` | OPTIONAL: add bullet under Key Features: "**PQC posture scanning** — audit TLS/SSH endpoints for post-quantum cryptography readiness against NIST FIPS 203 / OpenSSH PQ defaults". |

#### Step-by-Step

1. Write verdict + opt-out BDD tests; confirm fail.
2. Implement `PqcEngine.apply_extra_data()` final form.
3. Wire `pqc_no_active_probe` extra-arg by reading from `sub_step` (the engine receives the full sub_step dict per [base.py:268-274](../nettacker/core/lib/base.py#L268)) — the YAML's `pqc_no_active_probe: "{pqc_no_active_probe}"` field is templated by Nettacker's `TemplateLoader` from the operator's `--modules-extra-args`.
4. Write `docs/Modules.md` section.
5. Write `tests/e2e/test_pqc_scan_smoke.py` (skip-on-no-network).
6. Run static analysis + full tests.
7. Optionally update `README.md`.
8. Final `make test` + `pre-commit run --all-files`.

#### BDD Acceptance Scenarios

**Feature: Verdict, opt-out, docs**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| `pqc_ready` requires standardized | happy path | response with `tls_pqc_groups_advertised=["X25519MLKEM768"]`, table marks it `status="standardized"` | engine runs verdict logic | `verdict="pqc_ready"`; `compliance_notes` mentions FIPS 203 / draft-ietf-tls-ecdhe-mlkem |
| Draft-only does NOT trigger pqc_ready | invariant assertion | response with only a `status="draft"` algorithm | verdict logic | `verdict="hybrid_only"` or `"classical_only"` per actual classification — never `"pqc_ready"` |
| Hybrid-only correctly flagged | happy path | only hybrid algorithms advertised | verdict logic | `verdict="hybrid_only"`; `compliance_notes` says "hybrid PQ (e.g. X25519MLKEM768); transitional — does NOT meet CNSA 2.0 (ML-KEM-1024 required by 2027-01-01)" (F-CEO-1: CNSA 2.0 requires the 1024 parameter set) |
| ML-KEM-1024 advertised → CNSA-2.0-compliant note (F-CEO-1) | happy path | response with `tls_pqc_groups_advertised=["MLKEM1024"]` or `["SecP384r1MLKEM1024"]` | verdict logic | `verdict="pqc_ready"`; `compliance_notes` includes "meets CNSA 2.0 ML-KEM-1024 baseline" |
| Classical-only flagged | happy path | no PQC advertised | verdict logic | `verdict="classical_only"`; `compliance_notes` mentions "fails OpenSSH 10.1 WarnWeakCrypto baseline" or "fails OMB M-23-02 PQ baseline" depending on service |
| Unknown when probe failed | dependency failure | TCP refused | verdict logic | `verdict="unknown"`; `compliance_notes` is "scan inconclusive: <error reason>" |
| Opt-out skips active TLS probe | abuse-1 mitigation | `pqc_no_active_probe=true` | TLS step | `tls_pqc_scan` early-returns; SSH step still runs; structured log line says "active probe disabled by operator" |
| Opt-out preserves SSH path | abuse-1 | `pqc_no_active_probe=true` against SSH-only host | runs | normal SSH posture verdict |
| E2E smoke against public PQ-ready TLS | runtime | network available | `nettacker -m pqc_scan -i tls13.1d.pw` | exit 0, advertised list non-empty (depends on test endpoint availability — guard with `xfail_strict=False`) |
| E2E smoke against GitHub SSH | runtime | network available | `nettacker -m pqc_scan -i github.com --ports 22` | exit 0, advertised list contains at least one of the OpenSSH PQ algorithms |
| Existing modules still work | compatibility | full suite | `make test` | green |

#### Regression Tests

- Full `make test`.
- M1 + M2 BDD scenarios pass.
- `nettacker -m ssl_expiring_certificate_scan -i example.com` works.

#### Compatibility Checklist

- [ ] All existing modules unchanged.
- [ ] No new pip dep.
- [ ] Web UI module list shows `pqc_scan`.
- [ ] CLI `--help` shows no new top-level flags (extra-args is existing mechanism).
- [ ] Existing event-table schema unchanged.

#### E2E Runtime Validation

**File**: `tests/e2e/test_pqc_scan_smoke.py`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_smoke_tls_pqc_against_public_endpoint` | End-to-end: real CLI invocation against a real TLS endpoint that advertises PQC. | exit 0, output JSON contains `tls_pqc_groups_advertised` non-empty. |
| `test_smoke_ssh_pqc_against_github` | End-to-end: SSH posture against `github.com:22`. | exit 0, output contains expected OpenSSH PQ algorithm. |
| `test_smoke_opt_out_disables_tls_probe` | `pqc_no_active_probe=true` route is functional in CLI. | TLS path early-returns; SSH path still runs. |

#### Smoke Tests

- [ ] `poetry run nettacker -m pqc_scan -i tls13.1d.pw` returns `verdict=pqc_ready` (network-dependent).
- [ ] `poetry run nettacker -m pqc_scan -i github.com --ports 22` returns advertised SSH PQ algorithm.
- [ ] `poetry run nettacker -m pqc_scan -i 127.0.0.1 --modules-extra-args pqc_no_active_probe=true` works (opt-out).
- [ ] `pre-commit run --all-files` passes.
- [ ] `make test` (with `NETTACKER_NO_NETWORK_TESTS=1` for CI; without for local) passes.
- [ ] `docs/Modules.md` renders cleanly in mkdocs.

#### Evidence Log

(Filled per §13 template.)

#### Definition of Done

- All BDD scenarios pass.
- E2E smoke tests pass when network available; skipped cleanly when `NETTACKER_NO_NETWORK_TESTS=1`.
- `verdict` invariant `pqc_ready` ⇒ ≥1 standardized advertised — verified by parameterized tests.
- Opt-out exercised end-to-end.
- `docs/Modules.md` section reviewed for accuracy against actual response shape.
- `make test` baseline green.
- `pre-commit run --all-files` clean.
- `docs/slo/lessons/pqc-scanner-m3.md` written.
- `docs/slo/completion/pqc-scanner-m3.md` written.
- All three milestone tracker rows show status `done`.

#### Post-Flight

- **README.md**: optional one-bullet update to Key Features list.
- **`docs/Modules.md`**: new section.
- **Other docs**: lessons + completion.

#### Notes

- Public test endpoints can change. The e2e tests must be `@pytest.mark.e2e` and tolerant of test-host availability — consider `pytest.skip(reason="network test endpoint unreachable")` rather than failing if `tls13.1d.pw` returns no response.

---

## 18. Documentation Update Table

| Milestone | ARCHITECTURE.md Update | README.md Update | .gitignore Update | Other Docs |
|---|---|---|---|---|
| 1 | N/A (scope-doc lives in `docs/slo/design/pqc-compliance-scanner-architecture.md`) | none yet | add `evidence/` | lessons + completion |
| 2 | N/A | none yet | none new | lessons + completion |
| 3 | N/A | optional one-bullet add to Key Features | none new | `docs/Modules.md` NEW section; lessons + completion |

---

## 19. Optional Fast-Fail Review Prompt for Agents

Use the §19 verbiage from the v4 template before writing production code in any milestone.

---

## 20. Source Basis

This runbook is the v4 evolution of the SLO runbook template applied to a Python-stack feature inside an existing OWASP Foundation framework. The Carmack-style reliability rules (debugger-first inspection, mandatory static analysis, assertion-driven invariants, bounded resource design, "make invalid states unrepresentable") translate directly to Python via `assert`, `typing.Literal` / `typing.TypedDict`, ruff, and pre-commit. The 4.5 "make invalid states unrepresentable" guidance is implemented through `Literal` / `TypedDict` rather than Rust-style algebraic data types, but the discipline is the same.
