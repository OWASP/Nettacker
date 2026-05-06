# Stack Decision — pqc-compliance-scanner

## Chosen stack

**Python 3.10+** (matches Nettacker's [pyproject.toml](../../../pyproject.toml) `python = "^3.10, <3.13"`), implemented with:

- `socket` (stdlib) — raw TCP for both TLS ClientHello probing and SSH KEXINIT reading.
- `struct` (stdlib) — TLS 1.3 record / handshake framing per RFC 8446; SSH binary packet protocol per RFC 4253.
- `ssl` (stdlib, *for the existing fallback*) — re-used for the existing `ssl_certificate_scan` path; the new PQC probe code does NOT use `ssl.SSLContext.set_ciphers()` because Python's stdlib `ssl` does not expose TLS 1.3 named-group selection.
- `paramiko` (already a dep) — only as a *transport-banner reference*; the new SSH probe writes raw bytes for KEXINIT extraction because paramiko's `Transport` abstracts away the unilateral KEXINIT view we need.
- `pytest` + `pytest-asyncio` (already dev deps) — same conventions as [tests/core/lib/test_ssl.py](../../../tests/core/lib/test_ssl.py).

No new runtime deps. No new dev deps.

## Reason

The research synthesis ([synthesis.md](../research/pqc-compliance-scanner/synthesis.md)) sets three load-bearing constraints:

1. *"The design must implement TLS 1.3 ClientHello probing in pure Python (struct + socket), validate ServerHello / HelloRetryRequest / Alert response shapes, and never complete the handshake, because the academic technique already exists, validates, and lets us avoid both the oqsprovider dep and the connection-completion side effect"* — pulls us into stdlib-only TLS framing.
2. *"The design must read SSH KEXINIT directly from the wire ... rather than driving paramiko, because paramiko's high-level Transport abstracts away the advertisement view we want and silently negotiates regardless of PQC"* — pulls us into stdlib-only SSH framing.
3. *"The design must hardcode these two algorithm strings as the v1 SSH PQC allowlist ... because the OpenSSH project itself only ships these two as of 2026-05"* — eliminates the need for a runtime cryptography library on the client; we are pattern-matching strings, not cryptographic primitives.

Together these mean: no `cryptography` library, no `liboqs`, no `oqsprovider`, no `rustls`. Pure stdlib + the libs Nettacker already imports. This is the lowest-blast-radius path for the founder-confirmed "must be light and reliable" constraint and matches Nettacker's existing `nettacker/core/lib/ssl.py` style exactly.

## Rejected alternatives

- **Python `cryptography` (pyca) + native ML-KEM bindings** — pyca does not yet expose ML-KEM as of cryptography 44.x (May 2026); even if it did, we would not need crypto primitives because we're observing advertisements, not computing keys.
- **Shell out to `openssl s_client -groups`** (Approach B from idea doc) — requires OpenSSL 3.5+ and `oqsprovider` on the scanner host; locks the feature to Docker; makes a *real* PQ handshake against production endpoints (more invasive than passive enumeration); adds subprocess management overhead with no benefit for the wedge.
- **Ship `tlsfuzzer` or `nassl` as a vendored dep** — `tlsfuzzer` is test-fixture quality, not production-scanner quality; `nassl` requires a custom OpenSSL build and is a major supply-chain expansion. Both fail the "light and reliable" bar.

## Non-negotiables (downstream cannot change these without migration)

- Library file path: `nettacker/core/lib/pqc.py`. The Nettacker module loader at [nettacker/core/module.py:69-74](../../../nettacker/core/module.py#L69-L74) auto-discovers any `*.py` here, and at [module.py:156-159](../../../nettacker/core/module.py#L156-L159) imports `nettacker.core.lib.{library.lower()}` and instantiates `{library.capitalize()}Engine`. Renaming the file or class breaks YAML→Python binding for every existing PQC scan run.
- Library + engine class names: `PqcLibrary`, `PqcEngine`. Same rule.
- Public method names called from YAML: `tls_pqc_scan`, `ssh_pqc_scan`. These names appear in the YAML `method:` field — renaming requires updating every module YAML that references them.
- Pure stdlib + paramiko + pyopenssl. Adding any new runtime dep requires re-justifying against the "no new deps" constraint above.
- TLS ClientHello structure must remain strictly RFC 8446-conformant. Any deviation requires a documented safety review.
- Algorithm-name tables (`TLS_PQC_NAMED_GROUPS`, `SSH_PQC_KEX_ALGORITHMS`) live as module-level constants in `pqc.py` with codepoint citations in inline comments; updating them is a curation task, not a config change.
