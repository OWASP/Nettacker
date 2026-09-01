import re

import yaml

from nettacker import logger
from nettacker.config import Config

log = logger.get_logger()


class VersionDetails:
    """Nmap-style version templates extracted from a matched signature."""

    def __init__(
        self,
        raw,
        version_template=None,
        product=None,
        info=None,
        hostname=None,
        operating_device=None,
        device_type=None,
        cpe_service=None,
        cpe_os=None,
        cpe_h=None,
    ):
        self.raw = raw
        self.version_template = version_template
        self.product = product
        self.info = info
        self.hostname = hostname
        self.operating_device = operating_device
        self.device_type = device_type
        self.cpe_service = cpe_service
        self.cpe_os = cpe_os
        self.cpe_h = cpe_h


class Signature:
    """A single match/softmatch regex rule belonging to a probe."""

    def __init__(
        self,
        service,
        regex,
        sig_type="match",
        version_details=None,
        ignore_case=False,
        dotall=False,
    ):
        self.sig_type = sig_type
        self.service = service
        self.regex = regex
        self.version_details = version_details
        self.ignore_case = ignore_case
        self.dotall = dotall


class Probe:
    """An nmap-service-probes probe: the payload to send plus its signatures."""

    def __init__(
        self,
        name,
        protocol,
        totalwaits=6000,
        tcpwrappedms=3000,
        rarity=5,
        ports=None,
        sslports=None,
        fallbacks=None,
        probe_string="",
        no_payload=False,
        signatures=None,
    ):
        self.name = name
        self.protocol = protocol
        self.totalwaits = totalwaits
        self.tcpwrapped_ms = tcpwrappedms
        self.rarity = rarity
        self.ports = ports or []
        self.sslports = sslports or []
        self.fallbacks = fallbacks or []
        self.probe_string = probe_string
        self.no_payload = no_payload
        self.signatures = signatures or []


_PROBES_CACHE = None
_probes_by_name = {}
_excluded_ports = {"tcp": set(), "udp": set()}


def _parse_port_ranges(spec):
    """Expand a comma-separated port spec (e.g. "9100-9107,20005") into a set of ints."""
    ports = set()
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return ports


def _split_fallback_names(fallbacks):
    """Nmap's fallback directive separates multiple probe names with commas
    (e.g. "GetRequest,HTTPOptions"); split any entry that wasn't already split
    on the way in so each fallback resolves to a real probe name."""
    names = []
    for entry in fallbacks:
        names.extend(name.strip() for name in entry.split(",") if name.strip())
    return names


def load_probes_from_yaml():
    """Parse Config.path.probes_yaml_file into Probe objects, caching the result."""
    global _PROBES_CACHE
    global _probes_by_name

    if _PROBES_CACHE is not None:
        return _probes_by_name

    with open(Config.path.probes_yaml_file, "r", encoding="utf-8") as f:
        _PROBES_CACHE = yaml.safe_load(f)

    if not _PROBES_CACHE or "probes" not in _PROBES_CACHE:
        raise ValueError(f"No probes found in {Config.path.probes_yaml_file}")
    data = _PROBES_CACHE

    for excluded in data.get("Excluded ports") or []:
        universal = _parse_port_ranges(excluded.get("Universal", ""))
        _excluded_ports["tcp"] |= _parse_port_ranges(excluded.get("TCP", "")) | universal
        _excluded_ports["udp"] |= _parse_port_ranges(excluded.get("UDP", "")) | universal

    for p in data["probes"]:
        name = p["name"]
        protocol = p.get("protocol", "tcp").lower()
        totalwaits = int(p.get("totalwaits", 6000))
        tcpwrappedms = int(p.get("tcpwrappedms", 3000))
        rarity = int(p.get("rarity", 5))
        ports = p.get("ports", [])
        sslports = p.get("sslports", [])
        fallbacks = _split_fallback_names(p.get("fallbacks", []))
        # Every probe implicitly falls back to NULL - except NULL itself, which
        # would otherwise evaluate its own (thousands of) signatures twice.
        if name != "NULL" and "NULL" not in fallbacks:
            fallbacks.append("NULL")
        probe_string = p.get("probe_string", "")
        no_payload = p.get("no_payload", False)

        signatures = []
        for s in p.get("signatures", []):
            sig_type = s.get("type", "match")
            service = s.get("service", "")
            pattern = s.get("regex", "")
            ignore_case = bool(s.get("Ignore_case", False))
            new_line_specifier = bool(s.get("New_line_specifier", False))
            try:
                flags = 0
                if ignore_case:
                    flags |= re.IGNORECASE
                if new_line_specifier:
                    flags |= re.DOTALL
                regex = re.compile(pattern.encode("latin-1"), flags)
            except Exception as e:
                log.verbose_info(f"Probe signature failed to compile: {pattern!r} ({e})")
                continue
            v = s.get("version", {}) or {}
            version = VersionDetails(
                raw=v.get("raw", ""),
                version_template=v.get("version_template", ""),
                product=v.get("product", ""),
                info=v.get("info", ""),
                hostname=v.get("hostname", ""),
                operating_device=v.get("operating_device", ""),
                device_type=v.get("device_type", ""),
                cpe_service=(v.get("cpe", {}) or {}).get("cpe_service", ""),
                cpe_os=(v.get("cpe", {}) or {}).get("cpe_os", ""),
                cpe_h=(v.get("cpe", {}) or {}).get("cpe_h", ""),
            )
            signatures.append(
                Signature(
                    service=service,
                    regex=regex,
                    sig_type=sig_type,
                    version_details=version,
                    ignore_case=ignore_case,
                    dotall=new_line_specifier,
                )
            )

        probe = Probe(
            name=name,
            protocol=protocol,
            totalwaits=totalwaits,
            tcpwrappedms=tcpwrappedms,
            rarity=rarity,
            ports=ports,
            sslports=sslports,
            fallbacks=fallbacks,
            probe_string=probe_string,
            no_payload=no_payload,
            signatures=signatures,
        )
        # Keyed by (protocol, name): the probe database defines both a TCP and
        # a UDP probe under some shared names (Help, Kerberos, OpenVPN,
        # RPCCheck, SIPOptions) - a name-only key would silently drop one.
        _probes_by_name[(protocol, name)] = probe

    log.verbose_info(f"Loaded {len(_probes_by_name)} probes from {Config.path.probes_yaml_file}")
    return _probes_by_name


def build_probes_from_yaml():
    """Return the cached probes dict, loading it from YAML on first use."""
    if not _probes_by_name:
        load_probes_from_yaml()
    return _probes_by_name


def get_excluded_ports():
    """
    Return {"tcp": {port, ...}, "udp": {port, ...}} from the probe database's own
    "Excluded ports" directive (e.g. TCP 9100-9107, raw-print listeners that can
    physically print whatever payload is sent to them) - ports version detection
    must never send probe payloads to, regardless of which module selected them.
    """
    build_probes_from_yaml()
    return _excluded_ports
