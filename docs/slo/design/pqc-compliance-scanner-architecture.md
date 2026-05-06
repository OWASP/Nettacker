# Architecture — PQC compliance scanner (feature scope)

This is the **feature-scoped** architecture for the `pqc_scan` module. It does not document Nettacker's overall framework architecture (see [docs/CodebaseOverview.md](../../CodebaseOverview.md) for that).

## Component diagram

```
                               TRUST BOUNDARY
                              (operator's host)
                                      │
                                      │  internet / internal network
                                      │
┌─────────────────────────────────────┼──────────────────────────────────────┐
│  Nettacker process (existing)       │                                      │
│                                     │     ┌──────────────────────────┐     │
│  ┌──────────┐    ┌─────────────┐    │     │ Target endpoint          │     │
│  │   CLI    │    │   Web UI    │    │     │  - TLS server :443       │     │
│  │ (existing)│   │  (existing) │    │     │  - SSH server :22        │     │
│  └────┬─────┘    └──────┬──────┘    │     │  - other in port lists   │     │
│       │                 │           │     └─────▲──────────────┬─────┘     │
│       └────────┬────────┘           │           │              │           │
│                │                    │           │ probe        │ banner    │
│                ▼                    │           │ (1 conn      │ + KEXINIT │
│      ┌──────────────────┐           │           │  per group)  │ (1 conn)  │
│      │ Module loader    │           │           │              │           │
│      │ core/module.py   │           │           │              │           │
│      │ (existing)       │           │           │              │           │
│      └────────┬─────────┘           │           │              │           │
│               │ load YAML +         │           │              │           │
│               │ instantiate engine  │           │              │           │
│               ▼                     │           │              │           │
│      ┌────────────────────────┐     │           │              │           │
│      │ pqc_scan.yaml (NEW)    │     │           │              │           │
│      │ modules/scan/          │     │           │              │           │
│      └────────────┬───────────┘     │           │              │           │
│                   │ method:         │           │              │           │
│                   │  tls_pqc_scan   │           │              │           │
│                   │  ssh_pqc_scan   │           │              │           │
│                   ▼                 │           │              │           │
│      ┌────────────────────────┐     │           │              │           │
│      │ PqcLibrary +           │ ─ ─ ─ raw TCP, ─ ─ ─ ─ ─ ─ ─ ─┘           │
│      │ PqcEngine (NEW)        │ ─ ─ ─ stdlib socket   ─ ─ ─ ─ ─┘           │
│      │ core/lib/pqc.py        │           │                                │
│      └────────────┬───────────┘           │                                │
│                   │ verdict +             │                                │
│                   │ advertised list       │                                │
│                   ▼                       │                                │
│      ┌────────────────────────┐           │                                │
│      │ BaseEngine.process_    │           │                                │
│      │  conditions() (existing)│          │                                │
│      └────────────┬───────────┘           │                                │
│                   │ logs                  │                                │
│                   ▼                       │                                │
│         ┌─────────────────┐               │                                │
│         │ SQLite          │               │                                │
│         │ .nettacker/data │               │                                │
│         │ /nettacker.db   │               │                                │
│         │ (existing)      │               │                                │
│         └─────────────────┘               │                                │
│                                           │                                │
└───────────────────────────────────────────┼────────────────────────────────┘
                                            │
                                            └─── PUBLIC NETWORK
                                                 BOUNDARY
```

### Legend

- `solid box` = component that already exists in Nettacker.
- `(NEW)` = component this feature adds.
- `─►` solid arrow = data flow.
- `─ ─►` dashed arrow = network call (raw TCP, observation-only — no handshake completion).
- `TRUST BOUNDARY` = trust transition (operator's host vs. target endpoint).

## Data flow

1. Operator invokes the CLI / API / Web UI with `-m pqc_scan -i <target>` (or via the existing module list).
2. The existing module loader ([nettacker/core/module.py](../../../nettacker/core/module.py)) reads `nettacker/modules/scan/pqc_scan.yaml` (NEW), discovers `library: pqc`, imports `nettacker.core.lib.pqc` (NEW), instantiates `PqcEngine` (NEW), and dispatches per-step.
3. For each `(host, port)` tuple:
   - If the port is in the TLS port list, `PqcLibrary.tls_pqc_scan(host, port, timeout)` opens a TCP connection per probed PQC named-group codepoint, writes a strict-RFC-8446 ClientHello, reads at most one record, classifies the response (`ServerHello selected this group` / `HelloRetryRequest` / `handshake_failure alert` / `timeout`), and closes.
   - If the port is in the SSH port list, `PqcLibrary.ssh_pqc_scan(host, port, timeout)` opens a TCP connection, sends the SSH-2.0 client banner, reads the server banner + the first `MSG_KEXINIT` packet, parses the four advertised name-lists, and closes.
4. Library returns a dict `{tls_pqc_groups_advertised: [...], ssh_pqc_kex_advertised: [...], verdict: <enum>, compliance_notes: <str>, ...}`.
5. `PqcEngine.apply_extra_data()` (overridden) and `BaseEngine.process_conditions()` (existing) match against the YAML conditions block and log success events to the existing SQLite store.

## Trust boundaries

- **Operator host ↔ target endpoint**: classic pen-test trust boundary. Nettacker's existing disclaimer (README §DISCLAIMER) applies. The PQC module adds *one* new outbound surface per probed group — well within Nettacker's existing scan footprint.
- **Operator host internal**: target hostname/IP is operator-supplied; no privilege escalation surface added.
- **Persistence**: results land in the existing SQLite DB; no new persistence boundary, no new sensitive-key class.

## What this design intentionally does NOT do (v1 boundary)

- Does **not** complete TLS handshakes — only observes ServerHello / HRR / Alert.
- Does **not** verify cert-chain signature algorithms for PQ readiness — that is a v2 module (`tls_cert_pqc_scan`), and the verdict in v1 explicitly says so when classical RSA/ECDSA cert is detected via the existing `ssl_certificate_scan`.
- Does **not** scan SSH host-key algorithms for PQ — also v2.
- Does **not** ship its own port discovery — relies on Nettacker's existing `port_scan` (or operator-supplied port).
