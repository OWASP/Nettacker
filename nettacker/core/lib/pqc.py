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

# Placeholder: TLS named-groups table is finalized in M2. M1 keeps the constant
# defined-but-empty so test suites that reference it do not ImportError.
TLS_PQC_NAMED_GROUPS: dict[int, dict] = {}

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
