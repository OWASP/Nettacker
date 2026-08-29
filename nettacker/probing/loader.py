import re

import yaml

from nettacker.config import Config
from nettacker import logger

log = logger.get_logger()


class version_details:
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
        Signatures=None,
    ):
        self.name = name
        self.protocol = protocol
        self.totalwaits = totalwaits
        self.tcpwrapperdms = tcpwrappedms
        self.rarity = rarity
        self.ports = ports or []
        self.sslports = sslports or []
        self.fallbacks = fallbacks or []
        self.probe_string = probe_string
        self.no_payload = no_payload
        self.Signatures = Signatures or []


_PROBES_CACHE = None
_probes_by_name = {}


def load_probes_from_yaml():
    global _PROBES_CACHE
    global _probes_by_name

    if _PROBES_CACHE is not None:
        return _probes_by_name

    with open(Config.path.probes_yaml_file, "r", encoding="utf-8") as f:
        _PROBES_CACHE = yaml.safe_load(f)

    if not _PROBES_CACHE or "probes" not in _PROBES_CACHE:
        raise ValueError(f"No probes found in {Config.path.probes_yaml_file}")
    data = _PROBES_CACHE

    for p in data["probes"]:
        name = p["name"]
        protocol = p.get("protocol", "tcp").lower()
        totalwaits = int(p.get("totalwaits", 6000))
        tcpwrappedms = int(p.get("tcpwrappedms", 3000))
        rarity = int(p.get("rarity", 5))
        ports = p.get("ports", [])
        sslports = p.get("sslports", [])
        fallbacks = p.get("fallbacks", [])
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
            version = version_details(
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
            Signatures=signatures,
        )
        _probes_by_name[name] = probe

    log.verbose_info(f"Loaded {len(_probes_by_name)} probes from {Config.path.probes_yaml_file}")
    return _probes_by_name


def build_probes_from_yaml():
    if not _probes_by_name:
        load_probes_from_yaml()
    return _probes_by_name
