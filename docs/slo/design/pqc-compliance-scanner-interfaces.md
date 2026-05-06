# Interfaces — pqc-compliance-scanner

These are the public surfaces downstream milestones MUST keep stable without explicit migration work.

## CLI / module invocation

| Surface | Stability | Description |
|---|---|---|
| `nettacker -m pqc_scan -i <target>` | **stable** | Module name as it appears on the CLI. Renaming requires updating any saved scan-history references. |
| `--ports <list>` (existing global flag) | **stable** | Override default port list per Nettacker's existing convention. |
| `--excluded-ports <list>` (existing global flag) | **stable** | Filter ports from the default lists. |
| `--modules-extra-args` → `pqc_no_active_probe=true` | **stable** | NEW per-module extra-arg: when true, skip the active TLS ClientHello probe and run only the SSH KEXINIT-passive enumeration. Honors the founder-confirmed "must not crash the target" constraint by giving operators a passive-only fallback for fragile environments. |

## YAML module file

| Path | Stability | Description |
|---|---|---|
| `nettacker/modules/scan/pqc_scan.yaml` | **stable** | Module manifest. `info.name = pqc_scan`. Profiles include `scan`, `pqc`, `compliance`. |

YAML keys consumed (must match library method signatures):
- `payloads[].library: pqc`
- `payloads[].steps[].method: tls_pqc_scan` (calls `PqcLibrary.tls_pqc_scan(host, port, timeout)`)
- `payloads[].steps[].method: ssh_pqc_scan` (calls `PqcLibrary.ssh_pqc_scan(host, port, timeout)`)
- `payloads[].steps[].host: "{target}"`
- `payloads[].steps[].ports:` defaults — TLS step: `[443, 21, 25, 110, 143, 587, 990, 993, 995, 5061, 5222, 5269, 8443]`; SSH step: `[22, 2222]`.
- `payloads[].steps[].timeout: 5` seconds default per probe.
- `payloads[].steps[].response.condition_type: or` with conditions on `verdict` flags.

## Python library surface (`nettacker/core/lib/pqc.py`)

| Symbol | Stability | Description |
|---|---|---|
| `class PqcLibrary(BaseLibrary)` | **stable** | Public class; instantiated by the engine via `getattr(self.library(), method)` in `BaseEngine.run()`. |
| `class PqcEngine(BaseEngine)` | **stable** | Public class; auto-discovered via `{library.capitalize()}Engine` rule. |
| `PqcLibrary.tls_pqc_scan(host: str, port: int, timeout: int) -> dict` | **stable** | YAML method. Return shape below. |
| `PqcLibrary.ssh_pqc_scan(host: str, port: int, timeout: int) -> dict` | **stable** | YAML method. Return shape below. |
| `TLS_PQC_NAMED_GROUPS: dict[int, dict]` | **evolving** | Module-level table mapping IANA codepoint → `{name, kind, status, key_share_bytes, source}` where `kind ∈ {pure_pq, hybrid}`, `status ∈ {standardized, draft, experimental}`, `key_share_bytes` is the IETF-pinned client `key_exchange` octet length (see "PQC named-group key_share lengths" table below), `source` is the IETF / IANA citation. May grow with new IANA assignments. |
| `SSH_PQC_KEX_ALGORITHMS: dict[str, dict]` | **evolving** | Module-level table mapping OpenSSH algorithm string → `{kind, status, since_openssh_version}`. |
| Internal helpers (e.g. `_build_tls13_client_hello()`, `_parse_ssh_kexinit()`) | **internal** | Fair game to refactor. |

## PQC named-group `key_share` lengths (IETF-draft-pinned)

The TLS 1.3 `key_share` extension carries a `KeyShareEntry` per group: `{group: NamedGroup, key_exchange: opaque<1..2^16-1>}`. For our PQC probes the `key_exchange` payload is a **client-side** ML-KEM encapsulation key (or a concatenation of an ECDHE public point + ML-KEM encapsulation key for hybrids). The exact byte length per algorithm is fixed by the spec — sending the wrong length triggers a `decode_error` alert from the server, which our parser must distinguish from `handshake_failure` (= group recognized but unsupported).

We use a fixed all-zero buffer of the correct length as the client `key_exchange`. A real PQ client would send a freshly-generated ML-KEM encapsulation key, but since we never complete the handshake, the server only validates length, not key validity (we are observing whether it accepts the *shape* of a key share for this group, not negotiating).

| Codepoint | Name | `key_share_bytes` | Composition | Source |
|---:|---|---:|---|---|
| `0x0200` | `mlkem512` | 800 | ML-KEM-512 encapsulation key (FIPS 203) | [draft-ietf-tls-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/) §3 |
| `0x0201` | `mlkem768` | 1184 | ML-KEM-768 encapsulation key (FIPS 203) | [draft-ietf-tls-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/) §3 |
| `0x0202` | `mlkem1024` | 1568 | ML-KEM-1024 encapsulation key (FIPS 203) | [draft-ietf-tls-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/) §3 |
| `0x11EB` | `SecP256r1MLKEM768` | 1249 | secp256r1 uncompressed point (65 bytes, `0x04 ‖ X(32) ‖ Y(32)`) ‖ ML-KEM-768 encap key (1184) | [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/) §2 |
| `0x11EC` | `X25519MLKEM768` | 1216 | ML-KEM-768 encap key (1184) ‖ X25519 public key (32) — note: this group puts ML-KEM **first**, opposite of the SecP* hybrids; per draft §2 this is intentional. | [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/) §2 |
| `0x11ED` | `SecP384r1MLKEM1024` | 1665 | secp384r1 uncompressed point (97 bytes) ‖ ML-KEM-1024 encap key (1568) | [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/) §2 |

Updates to this table require updating the source citation. The total ClientHello byte length cap (1500 bytes per the M2 invariant) accommodates `SecP384r1MLKEM1024` plus extensions overhead.

## Library method response shape (`tls_pqc_scan` / `ssh_pqc_scan`)

```python
{
    # Always present
    "host": "example.com",
    "port": 443,
    "service": "tls" | "ssh",
    "scan_succeeded": bool,                    # True if we got any usable response
    "verdict": "pqc_ready" | "hybrid_only" | "classical_only" | "unknown",
    "compliance_notes": str,                   # human-readable, e.g. "fails OpenSSH 10.1 WarnWeakCrypto baseline"

    # TLS-specific (None for SSH)
    "tls_pqc_groups_advertised": list[str] | None,    # e.g. ["X25519MLKEM768", "MLKEM768"]
    "tls_pqc_groups_probed": list[str] | None,        # full list of groups we attempted
    "tls_classical_groups_advertised": list[str] | None,

    # SSH-specific (None for TLS)
    "ssh_pqc_kex_advertised": list[str] | None,       # e.g. ["mlkem768x25519-sha256"]
    "ssh_classical_kex_advertised": list[str] | None,
    "ssh_server_banner": str | None,

    # Operator diagnostics
    "errors": list[str],                       # e.g. ["timeout probing X25519MLKEM768", "TCP refused"]
    "duration_ms": int,
}
```

`verdict` semantics (locked):
- `pqc_ready` — server advertised at least one **standardized** PQC group/KEX (per `status: standardized` in the table).
- `hybrid_only` — server advertised only hybrid PQC, no pure PQC.
- `classical_only` — server responded successfully but advertised zero PQC algorithms.
- `unknown` — scan could not classify (timeout, TCP refused, malformed response, target not in scope of advertised port lists).

## Persisted-state shape

| Key | Stability | Description |
|---|---|---|
| Nettacker's existing `submit_logs_to_db()` shape | **inherited** | We do NOT introduce new DB columns. The full response dict above is serialized as YAML into the existing `event` column and as JSON into the existing `json_event` column, identical to all other modules. |

## `ignored_core_modules` registration

| Change | Stability | Description |
|---|---|---|
| Add `pqc_scan` to `ignored_core_modules` in [nettacker/core/module.py:48-58](../../../nettacker/core/module.py#L48-L58) | **stable** | Allows the operator to run `pqc_scan` directly without first running `port_scan`. Same pattern the existing `ssl_*` scans use. |

## Versioning policy

- Bumping algorithm tables (adding new IANA codepoints / OpenSSH algorithm strings) is a `patch` change.
- Changing `verdict` enum values, response field names, YAML method names, or the library/engine class names is a `minor` change at minimum, requires explicit deprecation comment in the codebase and a migration note in the PR description.
- Removing a `verdict` value or response field is a `major` change.
