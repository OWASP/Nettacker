"""Post-Quantum Cryptography (PQC) compliance scanner library.

Probes a TLS or SSH endpoint for the post-quantum cryptography algorithms
it advertises and emits a per-host posture verdict
(``pqc_ready`` / ``hybrid_only`` / ``classical_only`` / ``unknown``).

Design constraints (see ``docs/slo/design/pqc-compliance-scanner-*.md``):

* Single TCP connection per probe; the library never completes a TLS handshake.
* Strictly RFC 8446 (TLS 1.3) and RFC 4253 (SSH transport) conformant on the wire.
* No new runtime deps: stdlib socket / struct / re only.
* Server-controlled name strings are validated against RFC 4250 §6 charset before
  logging (CWE-117 mitigation).
* Every recoverable network exception is caught inside the library so
  ``BaseEngine.run`` retry loop is a no-op for probe failures (mitigates the
  CI-fanout outage abuse case in the threat model).
"""

import logging
import re
import socket
import struct
import time
from typing import Literal, TypedDict

from nettacker.core.lib.base import BaseEngine, BaseLibrary

log = logging.getLogger(__name__)

Verdict = Literal["pqc_ready", "hybrid_only", "classical_only", "unknown"]
Service = Literal["tls", "ssh"]


class PqcAlgorithmEntry(TypedDict):
    """One row of an algorithm table (SSH or TLS)."""

    kind: Literal["pure_pq", "hybrid"]
    status: Literal["standardized", "draft", "experimental"]
    source: str


class SshAlgorithmEntry(PqcAlgorithmEntry):
    since_openssh_version: str


# OpenSSH PQC KEX algorithms shipped as of 2026-05.
# Source: https://www.openssh.com/pq.html
# Table cap: 4 (per runbook M1 contract; also asserted at module-import time).
SSH_PQC_KEX_ALGORITHMS: dict[str, SshAlgorithmEntry] = {
    "sntrup761x25519-sha512@openssh.com": {
        "kind": "hybrid",
        "status": "standardized",
        "since_openssh_version": "9.0",
        "source": "https://www.openssh.com/pq.html",
    },
    "mlkem768x25519-sha256": {
        "kind": "hybrid",
        "status": "standardized",
        "since_openssh_version": "9.9",
        "source": "https://www.openssh.com/pq.html (default since 10.0)",
    },
    # Reserved slots — OpenSSH has stated future PQ signature algorithms on pq.html
    # but no concrete KEX additions as of 2026-05. Keeping the table cap visible
    # in code is the discipline (per runbook §4.4).
}
assert len(SSH_PQC_KEX_ALGORITHMS) <= 4, "SSH_PQC_KEX_ALGORITHMS table exceeds v1 cap of 4"

# TLS 1.3 PQC named-groups table (M2).
#
# Each entry: codepoint (IANA TLS NamedGroup) -> entry dict with:
#   - name:              IANA / IETF-draft canonical name string
#   - kind:              "pure_pq" or "hybrid"
#   - status:            "standardized" | "draft" | "experimental"
#   - key_share_bytes:   exact octet length of the client key_exchange field
#                        per draft-ietf-tls-mlkem-07 / draft-ietf-tls-ecdhe-mlkem-04
#                        (see docs/slo/design/pqc-compliance-scanner-interfaces.md
#                        "PQC named-group key_share lengths" table).
#   - source:            primary citation URL.
#
# Sending the wrong key_share length triggers a decode_error alert from the
# server, which our parser distinguishes from handshake_failure. The fixed
# all-zero buffer of correct length is a valid *shape* even though it would
# not yield a real shared secret — we never complete the handshake.
TLS_PQC_NAMED_GROUPS: dict[int, dict] = {
    0x0201: {
        "name": "MLKEM768",
        "kind": "pure_pq",
        "status": "standardized",
        "key_share_bytes": 1184,
        "source": "draft-ietf-tls-mlkem-07 §3",
    },
    0x0202: {
        "name": "MLKEM1024",
        "kind": "pure_pq",
        "status": "standardized",
        "key_share_bytes": 1568,
        "source": "draft-ietf-tls-mlkem-07 §3",
    },
    0x11EB: {
        "name": "SecP256r1MLKEM768",
        "kind": "hybrid",
        "status": "standardized",
        "key_share_bytes": 1249,  # 65 (secp256r1 uncompressed) + 1184 (ML-KEM-768)
        "source": "draft-ietf-tls-ecdhe-mlkem-04 §2",
    },
    0x11EC: {
        "name": "X25519MLKEM768",
        "kind": "hybrid",
        "status": "standardized",
        "key_share_bytes": 1216,  # 1184 (ML-KEM-768) + 32 (X25519); ML-KEM first
        "source": "draft-ietf-tls-ecdhe-mlkem-04 §2",
    },
    0x11ED: {
        "name": "SecP384r1MLKEM1024",
        "kind": "hybrid",
        "status": "standardized",
        "key_share_bytes": 1665,  # 97 (secp384r1 uncompressed) + 1568 (ML-KEM-1024)
        "source": "draft-ietf-tls-ecdhe-mlkem-04 §2",
    },
    # MLKEM512 (0x0200) deliberately excluded — no compliance framework requires
    # it and OpenSSL 3.5 / browsers / Cloudflare standardize on the 768/1024 tier
    # as of 2026-05.
}
assert len(TLS_PQC_NAMED_GROUPS) <= 8, "TLS_PQC_NAMED_GROUPS table exceeds v1 cap of 8"
for _cp, _entry in TLS_PQC_NAMED_GROUPS.items():
    assert 0 <= _cp <= 0xFFFF, f"TLS named-group codepoint out of range: {_cp:#x}"
    assert _entry["key_share_bytes"] > 0, f"key_share_bytes must be positive for {_cp:#x}"
del _cp, _entry

# TLS 1.3 ClientHello / record framing constants (RFC 8446)
_TLS_RECORD_HANDSHAKE = 22
_TLS_RECORD_ALERT = 21
_TLS_HANDSHAKE_CLIENT_HELLO = 1
_TLS_HANDSHAKE_SERVER_HELLO = 2
_TLS_LEGACY_VERSION = 0x0303  # TLS 1.2 wire version on ClientHello
_TLS_RECORD_MAX = 16384  # RFC 8446 §5.1 — TLSPlaintext.length max
_TLS_CLIENT_HELLO_MAX = 2048  # paranoid cap — accommodates SecP384r1MLKEM1024 (1810) + headroom
# Extension types (RFC 8446 §4.2)
_TLS_EXT_SERVER_NAME = 0
_TLS_EXT_SUPPORTED_GROUPS = 10
_TLS_EXT_SIGNATURE_ALGORITHMS = 13
_TLS_EXT_SUPPORTED_VERSIONS = 43
_TLS_EXT_KEY_SHARE = 51
# Three TLS 1.3 mandatory-to-implement cipher suites (RFC 8446 §B.4)
_TLS_CIPHER_SUITES_TLS13 = b"\x13\x01\x13\x02\x13\x03"
# HelloRetryRequest "magic" ServerHello.random (RFC 8446 §4.1.4)
_TLS_HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
# Signature-algorithms list (operator-trusted constant)
#   ecdsa_secp256r1_sha256 = 0x0403; rsa_pss_rsae_sha256 = 0x0804; ed25519 = 0x0807
_TLS_SIGALG_LIST = b"\x04\x03\x08\x04\x08\x07"

# RFC 4250 §6.4 algorithm-name charset: US-ASCII printable, no comma, no whitespace.
# See also draft-ietf-secsh-newmodes for the stricter regex used here. We follow
# the conservative subset used by OpenSSH itself.
_SSH_NAME_RE = re.compile(rb"\A[A-Za-z0-9._@+/-]+\Z")

_SSH_BANNER_MAX = 255  # RFC 4253 §4.2: SSH-2.0 banner cannot exceed 255 octets.
_SSH_PACKET_MAX = 35000  # RFC 4253 §6.1: packet length capped at 35000 octets.
_SSH_MSG_KEXINIT = 20  # SSH_MSG_KEXINIT byte
_SSH_KEXINIT_NAMELIST_COUNT = 10  # KEXINIT carries 10 name-lists per RFC 4253 §7.1
_SSH_CLIENT_BANNER = b"SSH-2.0-Nettacker_PQC_Scan\r\n"


def _safe_ssh_name(raw: bytes) -> str | None:
    """Validate one server-supplied SSH algorithm name against RFC 4250 §6.4 charset.

    Returns the decoded ASCII string when valid, ``None`` otherwise. ``None``
    return signals "drop this entry into errors with hex prefix" — the caller
    must not log the raw bytes (CWE-117 log-injection defence).
    """
    if not _SSH_NAME_RE.match(raw):
        return None
    return raw.decode("ascii")


def _parse_ssh_kexinit(payload: bytes) -> dict:
    """Parse one SSH_MSG_KEXINIT packet payload.

    ``payload`` is the packet payload starting with the message-type byte
    (``SSH_MSG_KEXINIT == 20``), followed by 16 bytes of cookie, then 10
    name-lists, two booleans, and a uint32 (per RFC 4253 §7.1).

    Returns a dict with the four name-list categories most relevant to PQC
    enumeration plus a ``_malformed`` list with hex-prefixes of any
    non-RFC-4250 names that were dropped.
    """
    if len(payload) < 1 + 16:
        raise ValueError("kexinit_payload_too_short")
    if payload[0] != _SSH_MSG_KEXINIT:
        raise ValueError(f"kexinit_unexpected_msg_type_{payload[0]}")

    pos = 1 + 16  # skip message type + cookie
    namelists: list[list[str]] = []
    malformed: list[str] = []

    for list_index in range(_SSH_KEXINIT_NAMELIST_COUNT):
        if pos + 4 > len(payload):
            raise ValueError(f"kexinit_truncated_at_namelist_{list_index}")
        (length,) = struct.unpack(">I", payload[pos : pos + 4])
        pos += 4
        if length > _SSH_PACKET_MAX:
            raise ValueError(f"kexinit_namelist_{list_index}_oversized_{length}")
        if pos + length > len(payload):
            raise ValueError(f"kexinit_namelist_{list_index}_truncated")
        raw = payload[pos : pos + length]
        pos += length
        names: list[str] = []
        if raw:
            for name_bytes in raw.split(b","):
                safe = _safe_ssh_name(name_bytes)
                if safe is None:
                    malformed.append(f"namelist{list_index}:{name_bytes[:16].hex()}")
                else:
                    names.append(safe)
        namelists.append(names)

    # Per RFC 4253 §7.1 the 10 lists are, in order:
    return {
        "kex_algorithms": namelists[0],
        "server_host_key_algorithms": namelists[1],
        "encryption_algorithms_client_to_server": namelists[2],
        "encryption_algorithms_server_to_client": namelists[3],
        "mac_algorithms_client_to_server": namelists[4],
        "mac_algorithms_server_to_client": namelists[5],
        "compression_algorithms_client_to_server": namelists[6],
        "compression_algorithms_server_to_client": namelists[7],
        "languages_client_to_server": namelists[8],
        "languages_server_to_client": namelists[9],
        "_malformed": malformed,
    }


def _read_ssh_banner(sock: socket.socket) -> bytes:
    """Read SSH server banner up to first ``\\n``, capped at 255 octets.

    Per RFC 4253 §4.2. Reads one byte at a time so we never over-consume into
    the next packet — the server is allowed to send the KEXINIT immediately
    after the banner, and recv'ing in larger chunks would silently drop the
    first KEXINIT bytes. Byte-at-a-time is what OpenSSH does on the wire and
    is fine for ≤255-octet banners.
    """
    buf = bytearray()
    while len(buf) < _SSH_BANNER_MAX:
        chunk = sock.recv(1)
        if not chunk:
            break
        buf.extend(chunk)
        if buf.endswith(b"\n"):
            break
    if not buf:
        raise ValueError("banner_empty")
    if not buf.endswith(b"\n"):
        # Read the cap without seeing a terminator — overflow.
        raise ValueError("banner_overflow_capped_at_255")
    line = bytes(buf).rstrip(b"\r\n")
    return line


def _read_ssh_packet(sock: socket.socket) -> bytes:
    """Read one SSH binary-packet payload (no MAC / encryption — pre-NEWKEYS).

    Wire format (RFC 4253 §6): uint32 packet_length, byte padding_length,
    payload, padding. Returns just the payload bytes.
    """
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise ValueError("packet_header_truncated")
        header += chunk
    (packet_length,) = struct.unpack(">I", header)
    if packet_length == 0 or packet_length > _SSH_PACKET_MAX:
        raise ValueError(f"packet_length_out_of_range_{packet_length}")
    body = b""
    while len(body) < packet_length:
        chunk = sock.recv(min(4096, packet_length - len(body)))
        if not chunk:
            raise ValueError("packet_body_truncated")
        body += chunk
    if len(body) < 1:
        raise ValueError("packet_body_missing_padding_length")
    padding_length = body[0]
    if 1 + padding_length > len(body):
        raise ValueError("packet_padding_overruns_body")
    return body[1 : len(body) - padding_length]


def _classify_ssh_kex(advertised: list[str]) -> tuple[list[str], list[str]]:
    """Split an advertised kex_algorithms list into (pqc, classical) buckets."""
    pqc = [name for name in advertised if name in SSH_PQC_KEX_ALGORITHMS]
    classical = [name for name in advertised if name not in SSH_PQC_KEX_ALGORITHMS]
    return pqc, classical


def _provisional_verdict_ssh(pqc: list[str]) -> Verdict:
    """Compute SSH verdict from advertised PQC list.

    M1 ships a provisional verdict; M3 finalizes the verdict logic with
    compliance_notes wording.
    """
    if not pqc:
        return "classical_only"
    standardized = [n for n in pqc if SSH_PQC_KEX_ALGORITHMS[n]["status"] == "standardized"]
    if standardized:
        return "pqc_ready"
    return "hybrid_only"


def _classify_tls_groups(advertised_codepoints: list[int]) -> tuple[list[str], list[int]]:
    """Split advertised TLS named-group codepoints into (pqc_names, classical_codepoints).

    Codepoints not in our PQC table are returned as numeric classical-codepoints
    (we don't carry a full classical group-name table; v2 may add).
    """
    pqc_names: list[str] = []
    classical: list[int] = []
    for cp in advertised_codepoints:
        if cp in TLS_PQC_NAMED_GROUPS:
            pqc_names.append(TLS_PQC_NAMED_GROUPS[cp]["name"])
        else:
            classical.append(cp)
    return pqc_names, classical


def _provisional_verdict_tls(pqc_names: list[str]) -> Verdict:
    """Compute TLS verdict from advertised PQC name list.

    M3 finalizes the wording; M2 ships a baseline that mirrors the SSH path.
    """
    if not pqc_names:
        return "classical_only"
    standardized = [
        n
        for n in pqc_names
        if any(
            entry["name"] == n and entry["status"] == "standardized"
            for entry in TLS_PQC_NAMED_GROUPS.values()
        )
    ]
    if standardized:
        return "pqc_ready"
    return "hybrid_only"


def _build_tls13_client_hello(
    group_codepoint: int,
    sni_host: str,
    *,
    client_random: bytes | None = None,
    legacy_session_id: bytes | None = None,
) -> bytes:
    """Construct one strict-RFC-8446 TLS 1.3 ClientHello for the given PQC group.

    Returns the full record-layer-framed bytes ready to ``sendall()``.

    The ClientHello carries one supported_groups entry, one matching key_share
    entry with a zero-buffer of the correct ``key_share_bytes`` length per
    the IETF-pinned table, the three TLS 1.3 cipher suites, and the standard
    extensions (server_name, supported_versions, signature_algorithms).

    ``client_random`` and ``legacy_session_id`` accept fixed bytes for
    deterministic golden-byte fixtures in tests; in production callers leave
    them ``None`` and the function generates fresh random bytes.

    Raises ``ValueError`` if ``group_codepoint`` is not in
    ``TLS_PQC_NAMED_GROUPS`` (defensive — the loop in ``tls_pqc_scan`` only
    iterates over the table so this can only fire from misuse). The emitted
    bytes are asserted to be ≤ ``_TLS_CLIENT_HELLO_MAX``.
    """
    if group_codepoint not in TLS_PQC_NAMED_GROUPS:
        raise ValueError(f"unknown_pqc_group_codepoint:{group_codepoint:#x}")
    entry = TLS_PQC_NAMED_GROUPS[group_codepoint]
    key_share_payload = b"\x00" * entry["key_share_bytes"]

    if client_random is None:
        import os

        client_random = os.urandom(32)
    if legacy_session_id is None:
        import os

        legacy_session_id = os.urandom(32)
    if len(client_random) != 32:
        raise ValueError("client_random must be 32 bytes")
    if len(legacy_session_id) > 32:
        raise ValueError("legacy_session_id must be ≤ 32 bytes")

    # ---- extension: server_name (RFC 6066 §3) ----
    sni_bytes = (
        sni_host.encode("idna")
        if any(ord(c) > 127 for c in sni_host)
        else sni_host.encode("ascii")
    )
    # NameType.host_name = 0; ServerName: opaque host_name<1..2^16-1>
    server_name_entry = b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
    server_name_list = struct.pack(">H", len(server_name_entry)) + server_name_entry
    ext_server_name = (
        struct.pack(">HH", _TLS_EXT_SERVER_NAME, len(server_name_list)) + server_name_list
    )

    # ---- extension: supported_versions (RFC 8446 §4.2.1) — TLS 1.3 only ----
    sv_payload = b"\x02\x03\x04"  # 1-byte length + uint16 0x0304
    ext_supported_versions = (
        struct.pack(">HH", _TLS_EXT_SUPPORTED_VERSIONS, len(sv_payload)) + sv_payload
    )

    # ---- extension: supported_groups (RFC 8446 §4.2.7) — single PQC group ----
    sg_list = struct.pack(">H", group_codepoint)
    sg_payload = struct.pack(">H", len(sg_list)) + sg_list
    ext_supported_groups = (
        struct.pack(">HH", _TLS_EXT_SUPPORTED_GROUPS, len(sg_payload)) + sg_payload
    )

    # ---- extension: signature_algorithms (RFC 8446 §4.2.3) ----
    sa_payload = struct.pack(">H", len(_TLS_SIGALG_LIST)) + _TLS_SIGALG_LIST
    ext_sigalgs = struct.pack(">HH", _TLS_EXT_SIGNATURE_ALGORITHMS, len(sa_payload)) + sa_payload

    # ---- extension: key_share (RFC 8446 §4.2.8) — single entry for the probed group ----
    ks_entry = struct.pack(">HH", group_codepoint, len(key_share_payload)) + key_share_payload
    ks_list = struct.pack(">H", len(ks_entry)) + ks_entry
    ext_key_share = struct.pack(">HH", _TLS_EXT_KEY_SHARE, len(ks_list)) + ks_list

    extensions = (
        ext_server_name
        + ext_supported_versions
        + ext_supported_groups
        + ext_sigalgs
        + ext_key_share
    )
    extensions_blob = struct.pack(">H", len(extensions)) + extensions

    # ---- ClientHello body (RFC 8446 §4.1.2) ----
    body = (
        struct.pack(">H", _TLS_LEGACY_VERSION)
        + client_random
        + struct.pack(">B", len(legacy_session_id))
        + legacy_session_id
        + struct.pack(">H", len(_TLS_CIPHER_SUITES_TLS13))
        + _TLS_CIPHER_SUITES_TLS13
        + b"\x01\x00"  # legacy_compression_methods<1..2^8-1>: vector of length 1, value 0
        + extensions_blob
    )

    # Handshake header: msg_type(1) + length(3, uint24)
    handshake_msg = (
        struct.pack(">B", _TLS_HANDSHAKE_CLIENT_HELLO)
        + struct.pack(">I", len(body))[1:]  # uint24 = drop high byte of uint32
        + body
    )

    # Record header: type(1) + legacy_record_version(2) + length(2)
    record = (
        struct.pack(">B", _TLS_RECORD_HANDSHAKE)
        + struct.pack(">H", _TLS_LEGACY_VERSION)
        + struct.pack(">H", len(handshake_msg))
        + handshake_msg
    )

    assert len(record) <= _TLS_CLIENT_HELLO_MAX, (
        f"emitted ClientHello exceeded paranoid cap "
        f"({len(record)} > {_TLS_CLIENT_HELLO_MAX}) for group {group_codepoint:#x}"
    )
    return record


def _parse_tls13_server_response(buf: bytes) -> dict:
    """Total parser — every ``bytes`` input maps to a tagged result.

    Returns one of:
      * ``{"kind": "server_hello", "selected_group": int | None, "is_hrr": bool}``
      * ``{"kind": "alert", "level": int, "description": int}``
      * ``{"kind": "unknown_record", "type": int}``
      * ``{"kind": "malformed", "reason": str}``

    Per F-SEC-2 invariant: this function MUST NOT raise. All structural
    errors are returned as ``{"kind": "malformed", ...}``. Random bytes
    map to ``malformed`` rather than producing a forged tagged result.
    """
    try:
        if len(buf) < 5:
            return {"kind": "malformed", "reason": "record_header_truncated"}
        record_type = buf[0]
        # buf[1:3] is legacy_record_version, ignored
        record_length = int.from_bytes(buf[3:5], "big")
        if record_length > _TLS_RECORD_MAX:
            return {"kind": "malformed", "reason": f"record_length_exceeds_cap_{record_length}"}
        if 5 + record_length > len(buf):
            # Allow shorter buffers — parse what we have, but flag truncation
            # for length-mismatch alerts later. For ServerHello/Alert we still
            # try to extract from what's present.
            pass
        record_body = buf[5 : 5 + record_length] if record_length > 0 else buf[5:]

        if record_type == _TLS_RECORD_ALERT:
            if len(record_body) < 2:
                return {"kind": "malformed", "reason": "alert_body_truncated"}
            return {"kind": "alert", "level": record_body[0], "description": record_body[1]}

        if record_type == _TLS_RECORD_HANDSHAKE:
            if len(record_body) < 4:
                return {"kind": "malformed", "reason": "handshake_header_truncated"}
            hs_type = record_body[0]
            hs_length = int.from_bytes(record_body[1:4], "big")
            hs_body = record_body[4 : 4 + hs_length]
            if hs_type != _TLS_HANDSHAKE_SERVER_HELLO:
                return {"kind": "malformed", "reason": f"unexpected_handshake_type_{hs_type}"}
            return _parse_server_hello_body(hs_body)

        return {"kind": "unknown_record", "type": record_type}
    except Exception as exc:  # pragma: no cover — F-SEC-2 invariant guard
        # Total-function discipline: any unforeseen bug becomes a malformed result,
        # not an escaping exception. The library outer-try catches this same class
        # too — defense in depth.
        return {"kind": "malformed", "reason": f"parser_internal:{type(exc).__name__}"}


def _parse_server_hello_body(body: bytes) -> dict:
    """Parse a ServerHello handshake body (post-handshake-header).

    Returns either ``{"kind": "server_hello", ...}`` or ``{"kind": "malformed", ...}``.
    HelloRetryRequest is a ServerHello with the magic random per RFC 8446 §4.1.4.
    """
    if len(body) < 2 + 32 + 1:
        return {"kind": "malformed", "reason": "server_hello_body_truncated"}
    pos = 2  # skip legacy_version (2 bytes)
    server_random = body[pos : pos + 32]
    pos += 32
    is_hrr = server_random == _TLS_HRR_RANDOM

    sid_len = body[pos]
    pos += 1
    if pos + sid_len > len(body):
        return {"kind": "malformed", "reason": "server_hello_session_id_truncated"}
    pos += sid_len

    # cipher_suite (2 bytes), legacy_compression_method (1 byte)
    if pos + 3 > len(body):
        return {"kind": "malformed", "reason": "server_hello_cipher_truncated"}
    pos += 3

    # extensions<6..2^16-1>
    if pos + 2 > len(body):
        return {"kind": "malformed", "reason": "server_hello_extensions_length_missing"}
    ext_total = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    if pos + ext_total > len(body):
        return {"kind": "malformed", "reason": "server_hello_extensions_truncated"}

    selected_group: int | None = None
    end = pos + ext_total
    while pos + 4 <= end:
        ext_type = int.from_bytes(body[pos : pos + 2], "big")
        ext_len = int.from_bytes(body[pos + 2 : pos + 4], "big")
        pos += 4
        if pos + ext_len > end:
            return {"kind": "malformed", "reason": "extension_truncated"}
        ext_data = body[pos : pos + ext_len]
        pos += ext_len
        if ext_type == _TLS_EXT_KEY_SHARE:
            # ServerHello key_share: KeyShareEntry { group, key_exchange<1..2^16-1> }
            # In an HRR, the key_share extension contains just the named group (no key).
            if len(ext_data) >= 2:
                selected_group = int.from_bytes(ext_data[:2], "big")

    return {
        "kind": "server_hello",
        "selected_group": selected_group,
        "is_hrr": is_hrr,
    }


def _empty_response(host: str, port: int, service: Service) -> dict:
    return {
        "host": host,
        "port": port,
        "service": service,
        "scan_succeeded": False,
        "verdict": "unknown",
        "compliance_notes": "scan inconclusive",
        "tls_pqc_groups_advertised": None,
        "tls_pqc_groups_probed": None,
        "tls_classical_groups_advertised": None,
        "ssh_pqc_kex_advertised": None,
        "ssh_classical_kex_advertised": None,
        "ssh_server_banner": None,
        "errors": [],
        "duration_ms": 0,
    }


class PqcLibrary(BaseLibrary):
    """PQC compliance scanner library.

    Two probe methods are exposed to YAML: ``ssh_pqc_scan`` (M1) and
    ``tls_pqc_scan`` (added in M2). Each opens exactly one TCP connection
    per (host, port) tuple, observes the server's unilateral advertisement,
    closes the socket, and returns a populated response dict.
    """

    def ssh_pqc_scan(self, host: str, port: int, timeout: int) -> dict:
        """Passive SSH PQC posture probe.

        Opens one TCP connection, sends the SSH-2.0 client banner, reads the
        server banner and one MSG_KEXINIT packet, closes the socket, and
        reports the advertised KEX algorithms classified into PQC vs classical.
        """
        port = int(port)
        timeout = int(timeout)
        response = _empty_response(host, port, "ssh")
        start = time.monotonic()
        sock: socket.socket | None = None
        try:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
            except ConnectionRefusedError:
                response["errors"].append("tcp_refused")
                return response
            except (socket.gaierror, OSError) as exc:
                response["errors"].append(f"tcp_error:{type(exc).__name__}")
                return response

            try:
                sock.sendall(_SSH_CLIENT_BANNER)
            except (socket.timeout, OSError) as exc:
                response["errors"].append(f"banner_send_failed:{type(exc).__name__}")
                return response

            try:
                banner = _read_ssh_banner(sock)
            except socket.timeout:
                response["errors"].append("banner_timeout")
                return response
            except ValueError as exc:
                response["errors"].append(str(exc))
                return response
            except OSError as exc:
                response["errors"].append(f"banner_io:{type(exc).__name__}")
                return response

            # Banner is server-controlled. Validate as printable-ASCII before logging
            # (CWE-117 mitigation). RFC 4253 §4.2 mandates printable US-ASCII for
            # the banner; we strip any non-printable bytes from the logged form.
            try:
                banner_decoded = banner.decode("ascii")
                if not all(32 <= ord(c) < 127 for c in banner_decoded):
                    raise UnicodeDecodeError("ascii", banner, 0, len(banner), "non-printable")
            except UnicodeDecodeError:
                response["errors"].append(f"malformed_banner:{banner[:32].hex()}")
                return response
            response["ssh_server_banner"] = banner_decoded

            try:
                payload = _read_ssh_packet(sock)
            except socket.timeout:
                response["errors"].append("kexinit_timeout")
                return response
            except ValueError as exc:
                response["errors"].append(str(exc))
                return response
            except OSError as exc:
                response["errors"].append(f"kexinit_io:{type(exc).__name__}")
                return response

            try:
                parsed = _parse_ssh_kexinit(payload)
            except ValueError as exc:
                response["errors"].append(str(exc))
                return response

            advertised = parsed["kex_algorithms"]
            pqc, classical = _classify_ssh_kex(advertised)
            response["ssh_pqc_kex_advertised"] = pqc
            response["ssh_classical_kex_advertised"] = classical
            response["scan_succeeded"] = True
            response["verdict"] = _provisional_verdict_ssh(pqc)
            response["compliance_notes"] = _ssh_compliance_notes(response["verdict"], pqc)
            for malformed_entry in parsed["_malformed"]:
                response["errors"].append(f"malformed_algorithm_name:{malformed_entry}")
            return response
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            response["duration_ms"] = int((time.monotonic() - start) * 1000)

    def tls_pqc_scan(self, host: str, port: int, timeout: int) -> dict:
        """Active TLS 1.3 PQC posture probe.

        For each PQC named-group codepoint in ``TLS_PQC_NAMED_GROUPS`` (≤8 in
        v1), open one TCP connection, send a strictly-RFC-8446-conformant
        ClientHello with that single group in supported_groups + key_share,
        read at most one TLS record back, classify the response
        (ServerHello-with-this-group / HelloRetryRequest / handshake_failure /
        decode_error / timeout), close the socket. We never complete the
        handshake.

        Per F-ENG-1 invariant: every recoverable network exception is caught
        and converted to ``errors=[…]`` so ``BaseEngine.run`` retry loop is a
        no-op for probe failures.
        """
        port = int(port)
        timeout = int(timeout)
        response = _empty_response(host, port, "tls")
        response["tls_pqc_groups_advertised"] = []
        response["tls_pqc_groups_probed"] = [
            entry["name"] for entry in TLS_PQC_NAMED_GROUPS.values()
        ]
        response["tls_classical_groups_advertised"] = []
        start = time.monotonic()
        any_response_observed = False

        try:
            for group_codepoint, entry in TLS_PQC_NAMED_GROUPS.items():
                group_name = entry["name"]
                outcome = _probe_one_tls_group(host, port, timeout, group_codepoint, group_name)
                if outcome["transport_failed"]:
                    # Hard transport error: likely affects every probe; record
                    # once and stop the loop to avoid hammering the target.
                    response["errors"].append(outcome["error"])
                    if not any_response_observed:
                        # No usable signal at all — surface as scan failure.
                        return response
                    break
                any_response_observed = True
                if outcome["advertised"]:
                    response["tls_pqc_groups_advertised"].append(group_name)
                if outcome["error"]:
                    response["errors"].append(outcome["error"])

            response["scan_succeeded"] = any_response_observed
            response["verdict"] = (
                _provisional_verdict_tls(response["tls_pqc_groups_advertised"])
                if any_response_observed
                else "unknown"
            )
            response["compliance_notes"] = _tls_compliance_notes(
                response["verdict"], response["tls_pqc_groups_advertised"]
            )
            return response
        finally:
            response["duration_ms"] = int((time.monotonic() - start) * 1000)


def _probe_one_tls_group(
    host: str,
    port: int,
    timeout: int,
    group_codepoint: int,
    group_name: str,
) -> dict:
    """One probe = one TCP connection. Returns outcome dict.

    Outcome keys:
      * ``advertised``: bool — is this group reported by the server?
      * ``error``: str | None — single-group diagnostic (None for clean reject)
      * ``transport_failed``: bool — True ⇒ the probe loop should abort
        (TCP refused / DNS error / timeout — likely affects every group)
    """
    sock: socket.socket | None = None
    try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
        except ConnectionRefusedError:
            return {"advertised": False, "error": "tcp_refused", "transport_failed": True}
        except (socket.gaierror, OSError) as exc:
            return {
                "advertised": False,
                "error": f"tcp_error:{type(exc).__name__}",
                "transport_failed": True,
            }

        try:
            client_hello = _build_tls13_client_hello(group_codepoint, host)
        except (ValueError, AssertionError) as exc:
            return {
                "advertised": False,
                "error": f"build_clienthello_failed_{group_name}:{type(exc).__name__}",
                "transport_failed": False,
            }

        try:
            sock.sendall(client_hello)
        except (socket.timeout, OSError) as exc:
            return {
                "advertised": False,
                "error": f"send_failed_{group_name}:{type(exc).__name__}",
                "transport_failed": False,
            }

        try:
            buf = sock.recv(_TLS_RECORD_MAX)
        except socket.timeout:
            return {
                "advertised": False,
                "error": f"timeout_{group_name}",
                "transport_failed": False,
            }
        except OSError as exc:
            return {
                "advertised": False,
                "error": f"recv_failed_{group_name}:{type(exc).__name__}",
                "transport_failed": False,
            }

        if not buf:
            return {
                "advertised": False,
                "error": f"tcp_closed_{group_name}",
                "transport_failed": False,
            }

        parsed = _parse_tls13_server_response(buf)
        return _classify_one_tls_response(parsed, group_codepoint, group_name)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _classify_one_tls_response(parsed: dict, group_codepoint: int, group_name: str) -> dict:
    """Translate a parsed ServerHello/Alert/etc. into an outcome dict."""
    kind = parsed["kind"]
    if kind == "server_hello":
        # Server selected a group OR sent HRR specifying a group.
        if parsed["selected_group"] == group_codepoint:
            return {"advertised": True, "error": None, "transport_failed": False}
        # Server selected a different group OR no key_share extension — treat as
        # not advertising the probed group (server has it ranked elsewhere or
        # not at all).
        return {"advertised": False, "error": None, "transport_failed": False}
    if kind == "alert":
        # handshake_failure = 40, illegal_parameter = 47, decode_error = 50,
        # protocol_version = 70 — distinguish "didn't recognize" from "decode error".
        # Per F-ENG-3 / F-CEO-1 the latter hints our key_share length is wrong.
        if parsed["description"] == 50:
            return {
                "advertised": False,
                "error": f"decode_error_for_{group_name}",
                "transport_failed": False,
            }
        # All other alerts (40, 47, 70, etc.) just mean "not supported" — clean signal.
        return {"advertised": False, "error": None, "transport_failed": False}
    if kind == "malformed":
        return {
            "advertised": False,
            "error": f"malformed_response_for_{group_name}:{parsed['reason']}",
            "transport_failed": False,
        }
    if kind == "unknown_record":
        return {
            "advertised": False,
            "error": f"unknown_record_type_{parsed['type']}_for_{group_name}",
            "transport_failed": False,
        }
    return {
        "advertised": False,
        "error": f"unexpected_response_kind_{kind}_for_{group_name}",
        "transport_failed": False,
    }


def _ssh_compliance_notes(verdict: Verdict, pqc: list[str]) -> str:
    """Render the SSH compliance_notes string for a given verdict.

    M1 ships a working baseline; M3 finalizes wording.
    """
    if verdict == "pqc_ready":
        return (
            "advertises standardized PQ KEX (" + ", ".join(pqc) + "); "
            "meets OpenSSH 10.1 WarnWeakCrypto baseline"
        )
    if verdict == "hybrid_only":
        return "advertises only draft / experimental PQ KEX; below standardized baseline"
    if verdict == "classical_only":
        return "no PQ KEX advertised; fails OpenSSH 10.1 WarnWeakCrypto baseline"
    return "scan inconclusive"


def _tls_compliance_notes(verdict: Verdict, pqc_names: list[str]) -> str:
    """Render the TLS compliance_notes string for a given verdict.

    M2 ships a working baseline; M3 finalizes the CNSA 2.0 / OMB M-23-02 wording.
    """
    if verdict == "pqc_ready":
        # F-CEO-1: only ML-KEM-1024 satisfies CNSA 2.0
        cnsa = any("MLKEM1024" in n for n in pqc_names)
        cnsa_note = (
            "; meets CNSA 2.0 ML-KEM-1024 baseline"
            if cnsa
            else "; transitional — CNSA 2.0 requires ML-KEM-1024 by 2027-01-01"
        )
        return f"advertises standardized PQ groups ({', '.join(pqc_names)}){cnsa_note}"
    if verdict == "hybrid_only":
        return "advertises only draft / experimental PQ groups; below standardized baseline"
    if verdict == "classical_only":
        return "no PQ groups advertised; fails OMB M-23-02 PQ baseline"
    return "scan inconclusive"


class PqcEngine(BaseEngine):
    """Engine binding YAML response.conditions to library output."""

    library = PqcLibrary

    def apply_extra_data(self, sub_step, response):
        """Populate ``conditions_results`` so ``BaseEngine.process_conditions``
        emits a success event for any successful PQC scan."""
        if isinstance(response, dict) and response.get("scan_succeeded"):
            sub_step["response"]["conditions_results"] = {
                "host": response["host"],
                "port": response["port"],
                "service": response["service"],
                "verdict": response["verdict"],
                "compliance_notes": response["compliance_notes"],
                "advertised_pqc": (
                    response.get("ssh_pqc_kex_advertised")
                    or response.get("tls_pqc_groups_advertised")
                    or []
                ),
            }
        else:
            sub_step["response"]["conditions_results"] = []
