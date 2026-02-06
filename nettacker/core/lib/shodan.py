import ipaddress
import json
from typing import Any

import requests

from nettacker.core.lib.base import BaseEngine, BaseLibrary
from nettacker.logger import get_logger

log = get_logger()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class ShodanLibrary(BaseLibrary):
    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str, timeout: float = 10.0) -> None:
        self.api_key = api_key
        self.timeout = timeout

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = dict(params or {})
        params["key"] = self.api_key
        resp = requests.get(f"{self.BASE_URL}{path}", params=params, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def resolve(self, hostnames: str) -> dict[str, Any]:
        """
        Resolve domain -> IP via Shodan DNS resolve.

        Returns a dict compatible with Nettacker conditions_results:
        - {} on failure
        - {"ip": ["x.x.x.x"], "log": "..."} on success
        """
        hostnames = (hostnames or "").strip()
        if not hostnames:
            return {}
        if _is_ip(hostnames):
            return {"ip": [hostnames], "log": f"Target is already an IP: {hostnames}"}
        data = self._get("/dns/resolve", params={"hostnames": hostnames})
        ip = data.get(hostnames)
        if not ip:
            # Sometimes API returns mapping for a normalized hostname; take the first IP if present.
            ip = next(iter(data.values()), None)
        if not ip:
            return {}
        return {"ip": [ip], "log": f"Resolved {hostnames} -> {ip}"}

    def host(self, ip: str, minify: bool = True) -> dict[str, Any]:
        """
        Fetch Shodan host information.

        Returns:
        - {} on failure
        - a dict (truthy) on success, with a human-friendly `log`.
        """
        ip = (ip or "").strip()
        if not ip:
            return {}
        data = self._get(f"/shodan/host/{ip}", params={"minify": "true" if minify else "false"})
        ip_str = data.get("ip_str") or ip

        ports = data.get("ports") or []
        org = data.get("org") or ""
        isp = data.get("isp") or ""
        asn = data.get("asn") or ""

        location = data.get("location") or {}
        country = location.get("country_name") or ""
        city = location.get("city") or ""

        hostnames = data.get("hostnames") or []
        domains = data.get("domains") or []
        tags = data.get("tags") or []
        vulns = sorted(list((data.get("vulns") or {}).keys()))
        last_update = data.get("last_update") or ""

        summary_parts = [f"Shodan host: {ip_str}"]
        if ports:
            summary_parts.append(f"ports={','.join(map(str, ports[:30]))}{'...' if len(ports) > 30 else ''}")
        if org:
            summary_parts.append(f"org={org}")
        if isp and isp != org:
            summary_parts.append(f"isp={isp}")
        if asn:
            summary_parts.append(f"asn={asn}")
        if country:
            summary_parts.append(f"loc={country}{'/' + city if city else ''}")
        if vulns:
            summary_parts.append(f"vulns={','.join(vulns[:20])}{'...' if len(vulns) > 20 else ''}")

        result: dict[str, Any] = {
            "log": " | ".join(summary_parts),
            "ip": ip_str,
            "ports": ports,
            "org": org,
            "isp": isp,
            "asn": asn,
            "country": country,
            "city": city,
            "hostnames": hostnames,
            "domains": domains,
            "tags": tags,
            "vulns": vulns,
            "last_update": last_update,
        }

        # Keep raw response small but useful for debugging/reporting.
        result["json_event"] = json.dumps(
            {
                "ip_str": ip_str,
                "ports": ports,
                "org": org,
                "isp": isp,
                "asn": asn,
                "location": {"country_name": country, "city": city},
                "hostnames": hostnames,
                "domains": domains,
                "tags": tags,
                "vulns": vulns,
                "last_update": last_update,
            }
        )
        return result


class ShodanEngine(BaseEngine):
    library = ShodanLibrary

    def run(
        self,
        sub_step,
        module_name,
        target,
        scan_id,
        options,
        process_number,
        module_thread_number,
        total_module_thread_number,
        request_number_counter,
        total_number_of_requests,
    ):
        api_key = (options.get("shodan_api_key") or "").strip()
        if not api_key:
            log.warn("Shodan API key missing; provide --modules-extra-args shodan_api_key=...")
            # Returning {} means "unsuccessful event" (no DB log written).
            sub_step["response"]["conditions_results"] = {}
            return self.process_conditions(
                sub_step,
                module_name,
                target,
                scan_id,
                options,
                {},
                process_number,
                module_thread_number,
                total_module_thread_number,
                request_number_counter,
                total_number_of_requests,
            )

        # Allow overriding network timeout via modules-extra-args shodan_timeout=...
        timeout = float(options.get("shodan_timeout") or 10.0)
        lib = ShodanLibrary(api_key=api_key, timeout=timeout)

        method = sub_step.get("method")
        backup_response = sub_step.get("response", {})

        # Honor dependency replacement using the shared BaseEngine mechanism.
        if "dependent_on_temp_event" in backup_response:
            temp_event = self.get_dependent_results_from_database(
                target, module_name, scan_id, backup_response["dependent_on_temp_event"]
            )
            sub_step = self.replace_dependent_values(sub_step, temp_event)

        try:
            if method == "resolve":
                result = lib.resolve(sub_step.get("hostnames", ""))
            elif method == "host":
                result = lib.host(
                    sub_step.get("ip", ""),
                    minify=bool(sub_step.get("minify", True)),
                )
            else:
                result = {}
        except requests.RequestException as e:
            log.warn(f"Shodan request failed: {e}")
            result = {}
        except Exception as e:
            log.warn(f"Shodan engine error: {e}")
            result = {}

        sub_step["response"]["conditions_results"] = result
        return self.process_conditions(
            sub_step,
            module_name,
            target,
            scan_id,
            options,
            result,
            process_number,
            module_thread_number,
            total_module_thread_number,
            request_number_counter,
            total_number_of_requests,
        )

