---
name: pqc-compliance-scanner
designed: 2026-05-06
tla_required: false    # no concurrent state machines, no consensus, no ordering across processes — single TCP connection per probe
security_libs_required: false   # no cryptographic operations performed; observation only
ai_component: false    # no LLM / agent component
compliance: [soc2, asvs, nist-800-53]   # buyer reads output to satisfy NIST SP 800-53 SC-13/SC-12 + OMB M-23-02 inventory; SOC 2 CC6.1; ASVS V6 (cryptography)
---

# Design overview — PQC compliance scanner

## What is being built
A new Nettacker scan module (`pqc_scan`) backed by a new library (`nettacker/core/lib/pqc.py`) that probes a TLS or SSH endpoint to enumerate the post-quantum cryptography algorithms it advertises. Output is a per-host posture verdict (`pqc_ready` / `hybrid_only` / `classical_only` / `unknown`) plus the list of advertised PQC algorithm names.

## Constraints on the design
1. **Lightweight + reliable** is the dominant constraint per founder confirmation 2026-05-06. One TCP connection per probed group; strictly RFC-compliant ClientHello shapes; no handshake completion.
2. **No new external system deps** — must work with the libraries already in `pyproject.toml` (stdlib socket/ssl/struct, paramiko, pyopenssl). No liboqs, no oqsprovider, no rustls.
3. **Fits Nettacker conventions exactly** — module YAML in `nettacker/modules/scan/`, library Python in `nettacker/core/lib/`, naming follows the `library.lower()` + `Library.capitalize() + Engine` rule from [nettacker/core/module.py:156-159](../../../nettacker/core/module.py#L156-L159).
4. **Per-asset input contract** — single host (URL / IP / `host:port`); when port omitted, use the default port lists from the existing TLS/SSH scans. Bulk scanning is the framework's job.

## Key file outputs (this design)
- `docs/slo/design/pqc-compliance-scanner-architecture.md` — diagram + data flow + trust boundaries (this feature scope only; not project-wide).
- `docs/slo/design/pqc-compliance-scanner-stack-decision.md` — chosen stack, rejected alternatives.
- `docs/slo/design/pqc-compliance-scanner-interfaces.md` — public APIs, YAML keys, response shape, algorithm-name tables.
- `docs/slo/design/pqc-compliance-scanner-security.md` — feature-scoped security defaults (project root `SECURITY.md` left untouched — it is OWASP Nettacker's vulnerability-disclosure policy, a different artifact).
- `docs/slo/design/pqc-compliance-scanner-threat-model.md` — STRIDE per component + abuse cases + compliance mapping.

## Why ARCHITECTURE.md is not at repo root
This feature is one scan module added to a 5-year-old framework with ~30 existing modules. Writing `ARCHITECTURE.md` at the repo root would falsely claim to describe the entire framework's architecture (which is partially documented in `docs/CodebaseOverview.md` and `docs/Developers.md` already). The architecture doc is therefore scoped to this feature and lives under `docs/slo/design/`.

## Why SECURITY.md is not regenerated
[SECURITY.md](../../../SECURITY.md) at the repo root is OWASP Nettacker's vulnerability-disclosure policy (where to report a vuln *in* Nettacker). The slo-architect skill's "project-wide security defaults" template would replace that — which would harm OWASP's disclosure operations. Feature-scoped security defaults (cipher allowlists, ClientHello shape rules, rate caps, opt-out flag) live in [pqc-compliance-scanner-security.md](pqc-compliance-scanner-security.md) instead.

## tla_required justification
False. The system does no concurrent state sharing, no consensus, no resource leasing, no failure-recovery protocol. State per probe is `(target_host, target_port, named_group_codepoint) → ServerHello | HRR | Alert | timeout`. The only concurrency is Nettacker's existing per-host thread pool — the framework already enforces ordering and rate. No spec needed.

## Hand off to /slo-plan
All five design artifacts complete. Next: `/slo-plan pqc-compliance-scanner`.
