"""Every module's default ports must be ports that port_scan probes.

With service discovery enabled (the default), ``Module.load()`` in
``nettacker/core/module.py`` removes any payload whose library (``http``,
``ssh``, ...) ``port_scan`` did not discover on the target. ``port_scan`` only
connects to the ports listed in ``nettacker/modules/scan/port.yaml``, so a
module whose default port is missing from that list never runs against a host
that only exposes the service on that port, and the scan ends with
"no any live service found to scan." without any error.

``port.yaml`` follows Nmap's default port list. The non-standard default ports
that only Nettacker modules use are kept in a separate, commented block at the
end of that list.
"""

from pathlib import Path

import pytest
import yaml

MODULES_DIR = Path(__file__).resolve().parents[2] / "nettacker" / "modules"
PORT_SCAN_FILE = MODULES_DIR / "scan" / "port.yaml"

# Mirrors Module.ignored_core_modules in nettacker/core/module.py: service
# discovery never removes payloads from these modules.
IGNORED_CORE_MODULES = {
    "subdomain_scan",
    "icmp_scan",
    "port_scan",
    "ssl_weak_version_vuln",
    "ssl_weak_cipher_vuln",
    "ssl_certificate_weak_signature_vuln",
    "ssl_self_signed_certificate_vuln",
    "ssl_expired_certificate_vuln",
    "ssl_expiring_certificate_scan",
}


def load_yaml(path):
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


PORT_SCAN_STEP = load_yaml(PORT_SCAN_FILE)["payloads"][0]["steps"][0]
PORT_SCAN_PORTS = set(PORT_SCAN_STEP["ports"])
# Payload libraries that service discovery can remove
# (Module.service_discovery_signatures).
SERVICE_SIGNATURES = set(PORT_SCAN_STEP["response"]["conditions"]["service"])


def module_id(path):
    """Module id as ArgParser.load_modules builds it: <file stem>_<category>."""
    return f"{path.stem}_{path.parent.name}"


def collect_ports(node):
    """Return every integer listed under a ``ports`` key, at any depth."""
    ports = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "ports" and isinstance(value, list):
                ports.update(port for port in value if isinstance(port, int))
            else:
                ports |= collect_ports(value)
    elif isinstance(node, list):
        for item in node:
            ports |= collect_ports(item)
    return ports


MODULE_FILES = sorted(
    path
    for path in MODULES_DIR.glob("*/*.yaml")
    if path != PORT_SCAN_FILE and module_id(path) not in IGNORED_CORE_MODULES
)


def test_port_scan_list_has_no_duplicate_or_invalid_ports():
    ports = PORT_SCAN_STEP["ports"]
    assert len(ports) == len(set(ports))
    assert all(isinstance(port, int) and 1 <= port <= 65535 for port in ports)


@pytest.mark.parametrize("module_file", MODULE_FILES, ids=module_id)
def test_module_default_ports_are_probed_by_port_scan(module_file):
    missing = set()
    for payload in load_yaml(module_file).get("payloads", []):
        if payload.get("library") in SERVICE_SIGNATURES:
            missing |= collect_ports(payload.get("steps", [])) - PORT_SCAN_PORTS

    assert not missing, (
        f"{module_id(module_file)} uses default port(s) {sorted(missing)} that port_scan "
        "never probes, so service discovery skips the module on hosts that only expose "
        "those ports. Add them to nettacker/modules/scan/port.yaml."
    )
