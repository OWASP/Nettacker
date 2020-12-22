#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import socks
import time
import json
import threading
import logging
import requests
from core.alert import warn, info, messages
from lib.socks_resolver.engine import getaddrinfo
from core.targets import target_type
from core.targets import target_to_host
from core._time import now
from core.log import __log_into_file
import shodan


def extra_requirements_dict():
    return {
        "shodan_api_key": ["your_shodan_api_key_here"],
        "shodan_query_override": [""],
        "shodan_results": [],
    }

HOST_URL = "https://api.shodan.io/shodan/host/search?key="

def __shodan_scan(
    target,
    timeout_sec,
    log_in_file,
    time_sleep,
    language,
    verbose_level,
    socks_proxy,
    retries,
    headers,
    extra_requirements,
):
    try:
        if socks_proxy is not None:
            socks_version = (
                socks.SOCKS5
                if socks_proxy.startswith("socks5://")
                else socks.SOCKS4
            )
            socks_proxy = socks_proxy.rsplit("://")[1]
            if "@" in socks_proxy:
                socks_username = socks_proxy.rsplit(":")[0]
                socks_password = socks_proxy.rsplit(":")[1].rsplit("@")[0]
                socks.set_default_proxy(
                    socks_version,
                    str(socks_proxy.rsplit("@")[1].rsplit(":")[0]),
                    int(socks_proxy.rsplit(":")[-1]),
                    username=socks_username,
                    password=socks_password,
                )
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
            else:
                socks.set_default_proxy(
                    socks_version,
                    str(socks_proxy.rsplit(":")[0]),
                    int(socks_proxy.rsplit(":")[1]),
                )
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        test_query = "8.8.8.8"
        shodan_api_key = extra_requirements["shodan_api_key"][0]
        shodan_query = extra_requirements["shodan_query_override"][0]
        key = shodan.Shodan(shodan_api_key)
        dnsipresults = None
        try:
            key.host(test_query)
        except shodan.APIError as error:
            warn(messages(language, "Invalid_shodan_api_key").format(error))
            return []
        if shodan_query:
            info(messages(language, "using_shodan_query_override").format(shodan_query))
            list_query = shodan_query.split(" ")
            for i in list_query:
                target_final = i.split(":")
                try:
                    if "." in target_final[1]:
                        target = target_final[1]
                        break
                except IndexError:
                    pass
            shodan_url = (
                HOST_URL
                + shodan_api_key
                + "&query="
                + shodan_query
            )
        else:
            if target_type(target) == "SINGLE_IPv4":
                shodan_url = (
                    HOST_URL
                    + shodan_api_key
                    + "&query=ip:"
                    + target
                )
            else:
                shodan_url = (
                    HOST_URL
                    + shodan_api_key
                    + "&query=hostname:"
                    + target
                )
                dnsip = (
                    "https://api.shodan.io/dns/resolve?hostnames="
                    + target
                    + "&key="
                    + shodan_api_key
                )
                dnsipreq = requests.get(dnsip, verify=False, headers=headers)
                dnsipresults = json.loads(dnsipreq.text)[target]
        try:
            req = requests.get(shodan_url, verify=False, headers=headers)
        except Exception:
            warn(
                messages(language, "input_target_error").format(
                    "shodan", target
                )
            )
            return []
        try:
            results = json.loads(req.text)["matches"]
        except Exception:
            warn(messages(language, "shodan_plan_upgrade"))
            if ":" in shodan_query:
                return []
            
            shodan_url = (
                HOST_URL
                + shodan_api_key
                + "&query="
                + target
            )
            req = requests.get(shodan_url, verify=False, headers=headers)
            results = json.loads(req.text)["matches"]
            if not results:
                if dnsipresults is None:
                    return []
                shodan_url = (
                    HOST_URL
                    + shodan_api_key
                    + "&query=ip:"
                    + dnsipresults
                )
                req = requests.get(shodan_url, verify=False, headers=headers)
                results = json.loads(req.text)["matches"]
        if not results and target_type(target) != "SINGLE_IPv4":
            if dnsipresults is None:
                return []

            shodan_url = (
                HOST_URL
                + shodan_api_key
                + "&query=ip:"
                + dnsipresults
            )
            req = requests.get(shodan_url, verify=False, headers=headers)
            try:
                results = json.loads(req.text)["matches"]
                if not results:
                    shodan_url = (
                        HOST_URL
                        + shodan_api_key
                        + "&query=ip:"
                        + dnsipresults
                    )
                    req = requests.get(
                        shodan_url, verify=False, headers=headers
                    )
                    results = json.loads(req.text)["matches"]
            except Exception:
                info(messages(language, "shodan_results_not_found"))
                return []
        for i in range(len(results)):
            subsearch = []
            subsearch.append(
                str(results[i]["ip_str"]) + ":" + str(results[i]["port"])
            )
            subsearch.append(results[i]["data"][:200])
            try:
                subsearch.append(
                    "Country: " + results[i]["location"]["country_name"]
                )
            except Exception:
                pass
            try:
                subsearch.append("Org: " + results[i]["org"])
            except Exception:
                pass
            try:
                for j in results[i]["cpe"]:
                    subsearch.append(j)
            except Exception:
                pass
            try:
                for j in results[i]["_shodan"]["options"]:
                    if j == "hostname":
                        subsearch.append(results[i]["_shodan"]["options"][j])
            except Exception:
                pass
            try:
                for key in results[int(i)]["vulns"].keys():
                    subsearch.append(
                        str(key) + "&cvss: " + str(results[int(i)]["vulns"][key]["cvss"])
                    )
            except Exception:
                pass
            if (
                "\n".join(subsearch)
                not in extra_requirements["shodan_results"]
            ):
                extra_requirements["shodan_results"].append(
                    "\n".join(subsearch)
                )

        return extra_requirements["shodan_results"]
    except Exception:
        return []


def __shodan(
    target,
    timeout_sec,
    log_in_file,
    time_sleep,
    language,
    verbose_level,
    socks_proxy,
    retries,
    num,
    total,
    extra_requirements=extra_requirements_dict(),
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)\
             AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;\
            q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    },
):
    total_req = 0
    trying = 0
    threads = []
    for key in extra_requirements:
        try:
            if extra_requirements[key][0] == "True":
                total_req += 1
        except IndexError:
            pass
    trying += 1
    if verbose_level > 3:
        info(
            messages(language, "trying_process").format(
                trying, total_req, num, total, target, "shodan_scan"
            )
        )
    t = threading.Thread(
        target=__shodan_scan,
        args=(
            target,
            timeout_sec,
            log_in_file,
            time_sleep,
            language,
            verbose_level,
            socks_proxy,
            retries,
            headers,
            extra_requirements,
        ),
    )
    threads.append(t)
    t.start()
    threads.append(t)
    # wait for threads
    kill_switch = 0
    kill_time = int(timeout_sec / 0.1) if int(timeout_sec / 0.1) != 0 else 1
    while 1:
        time.sleep(0.1)
        kill_switch += 1
        try:
            if threading.activeCount() == 1 or (
                kill_time != -1 and kill_switch == kill_time
            ):
                break
        except KeyboardInterrupt:
            break
    result = []
    try:
        result = __shodan_scan(
            target,
            timeout_sec,
            log_in_file,
            time_sleep,
            language,
            verbose_level,
            socks_proxy,
            retries,
            headers,
            extra_requirements,
        )
    except Exception:
        result = []
    return result


def start(
    target,
    users,
    passwds,
    ports,
    timeout_sec,
    thread_number,
    num,
    total,
    log_in_file,
    time_sleep,
    language,
    verbose_level,
    socks_proxy,
    retries,
    methods_args,
    scan_id,
    scan_cmd,
):  # Main function
    info(messages(language, "searching_shodan_database").format(target))
    if (
        target_type(target) != "SINGLE_IPv4"
        or target_type(target) != "DOMAIN"
        or target_type(target) != "HTTP"
        or target_type(target) != "SINGLE_IPv6"
    ):
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[
                        extra_requirement
                    ]
        extra_requirements = new_extra_requirements
        if target_type(target) == "HTTP":
            target = target_to_host(target)

        result = __shodan(
            target,
            timeout_sec,
            log_in_file,
            time_sleep,
            language,
            verbose_level,
            socks_proxy,
            retries,
            num,
            total,
            extra_requirements=extra_requirements,
        )
        count = 0
        if len(result) == 0:
            info(messages(language, "shodan_results_not_found"))
        if len(result) != 0:
            info(
                messages(language, "shodan_results_found").format(len(result))
            )
            for parts in result:
                if verbose_level > 2:
                    info(
                        messages(language, "shodan_results_found").format(
                            parts
                        )
                    )
                try:
                    data = (
                        json.dumps(
                            {
                                "HOST": str(parts)
                                .split("\n")[0]
                                .split(":")[0],
                                "USERNAME": "",
                                "PASSWORD": "",
                                "PORT": str(parts)
                                .split("\n")[0]
                                .split(":")[1],
                                "TYPE": "shodan_scan",
                                "DESCRIPTION": parts,
                                "TIME": now(),
                                "CATEGORY": "scan",
                                "SCAN_ID": scan_id,
                                "SCAN_CMD": scan_cmd,
                            }
                        )
                        + "\n"
                    )
                    __log_into_file(log_in_file, "a", data, language)
                    count += 1
                except Exception:
                    pass
        if len(result) == 0 and verbose_level != 0:
            data = (
                json.dumps(
                    {
                        "HOST": target,
                        "USERNAME": "",
                        "PASSWORD": "",
                        "PORT": "",
                        "TYPE": "shodan_scan",
                        "DESCRIPTION": messages(
                            language, "subdomain_found"
                        ).format(
                            len(result),
                            ", ".join(result) if len(result) > 0 else "None",
                        ),
                        "TIME": now(),
                        "CATEGORY": "scan",
                        "SCAN_ID": scan_id,
                        "SCAN_CMD": scan_cmd,
                    }
                )
                + "\n"
            )
            __log_into_file(log_in_file, "a", data, language)
        return result
    else:
        warn(
            messages(language, "input_target_error").format(
                "shodan_scan", target
            )
        )
        return []
