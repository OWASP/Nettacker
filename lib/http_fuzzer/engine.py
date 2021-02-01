#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import json
import socket
import socks
import requests
import itertools
import threading
import os
from core.alert import info, messages
from core.log import __log_into_file
import random
from core.targets import target_type
from lib.socks_resolver.engine import getaddrinfo
from lib.payload.wordlists import useragents

value1 = None

def simple_test_open_url(url):
    """
    Simply open a URL using GET request.

    Args:
        url: url to open

    Returns:
        True if response available, otherwise False
    """
    try:
        return requests.get(url, headers={"User-Agent": random.choice(useragents.useragents())}).status_code
    except Exception as _:
        return False


def target_builder(target, ports, default_ports):
    """
    build HTTP target type from host or any!

    Args:
        target: raw target
        ports: ports array
        default_ports: default ports in case user not entered, in array type

    Returns:
        [] if cannot open URL, otherwise a list of valid URLs
    """
    methods = ["http", "https"]
    if not ports:
        ports = default_ports
    URL = []
    if target_type(target) != "HTTP":
        for port in ports:
            for method in methods:
                if simple_test_open_url(
                    method + "://" + target + ":" + str(port) + "/"
                ):
                    URL.append(method + "://" + target + ":" + str(port))
    else:
        if not simple_test_open_url(target):
            return []
        URL.append(target)
    return URL


def post_data_parser(post_data):
    """
    this function parses the post request format when the content type is application/x-www-form-urlencoded. It converts
    the post request parameters to a json dictionary that can be passed to requests library as data

    Args:
        post_data: post data to do the progress

    Returns:
         a dictionary that can be passed to requests library as data

    """
    post_data_json = {}
    for parameter in post_data.rsplit("&"):
        post_data_json[parameter.rsplit("=")[0]] = parameter.rsplit("=")[1]
    return post_data_json


def __http_requests_generator(request_template, parameters):
    """
    this function generates the actual requests from the template of the request

    Args:
        request_template: the template into which the payload is to be filled
        parameters: the payload in form of [[1,2,3], [1,2,3],...]

    Returns:
         the requests by filling in the parameter data into the template

    """
    for payload in itertools.product(*parameters):
        yield request_template.format(*payload), payload


def __http_request_maker(
    req_type,
    url,
    headers,
    retries,
    time_sleep,
    timeout_sec=None,
    data=None,
    content_type=None,
    socks_proxy=None,
):
    """
    this function performs the actual requests using the requests library according to the given type
    Supported types are GET, POST, PUT, DELETE, PATCH

    Args:
        req_type: GET, POST, PUT, DELETE or PATCH
        content_type: application/json or application/x-www-form-urlencoded
        other args: url, headers, retries, time_sleep, timeout_sec, data

    Returns:
         the response of the request made otherwise 0

    """
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
    exits = 0
    r = None
    while True:
        try:
            req_type = req_type.lower()
            if req_type in ["post", "put", "patch"]:
                if content_type == "application/data":
                    r = eval(
                        "requests.{}(url=url, headers=headers, data=data,\
                             timeout=timeout_sec, verify=False)".format(
                            req_type
                        )
                    )
                elif content_type == "application/json":
                    r = eval(
                        "requests.{}(url=url, headers=headers, json=data,\
                             timeout=timeout_sec, verify=False)".format(
                            req_type
                        )
                    )
            elif req_type in ["get", "head", "delete"]:
                r = eval(
                    "requests.{}(url=url, headers=headers,\
                         verify=False, timeout=timeout_sec)".format(
                        req_type
                    )
                )
            break
        except Exception as _:
            exits += 1
            if exits is retries:
                return 0
            else:
                time.sleep(time_sleep)
                continue
    return r


def request_with_data(
    post_request,
    content_type,
    req_type,
    retries,
    time_sleep,
    timeout_sec,
    payload,
    condition,
    output,
    sample_event,
    message,
    log_in_file,
    thread_tmp_filename,
    language,
    targets,
    ports,
    default_ports,
    socks_proxy,
):
    """
    this function extracts the data, headers and url for the POST type request which is to be sent to
    the __http_request_maker function

    Args:
        post_request: the returned data from __http_requests_generator function
        req_type: GET, POST, PUT, DELETE or PATCH
        content_type: application/json or application/x-www-form-urlencoded
        payload: the payload corresponding to which the request is made
        condition: the condition to be evaluated. eg: response.status_code == 200
        other args: retries, time_sleep, timeout_sec, output, sample_event, message, log_in_file,
        thread_tmp_filename, language

    Returns:
         the list of outputs in the format
            [
                {
                    "payload": payload,
                    "condition": condition,
                    "result": rule_evaluator(response, condition),
                    "response": response
                },......
            ]

    """
    post_data_format = ""
    request_line, headers_alone = post_request.split("\r\n", 1)
    headers = dict()
    try:
        for x in headers_alone.split("\r\n"):
            headers[x.split(":", 1)[0]] = x.split(":", 1)[1]
    except IndexError:
        headers[headers_alone.split(":", 1)[0]] = headers_alone.split(":", 1)[
            1
        ]
    clean_headers = {x.strip(): y.strip() for x, y in headers.items()}
    headers = clean_headers
    if "content-type" in headers:
        content_type = headers["content-type"]
        if content_type == "application/x-www-form-urlencoded":
            post_data_format = post_data_parser(post_request.split("\r\n")[-1])
        elif content_type == "application/json":
            post_data_format = json.loads(
                post_request[
                    post_request.find("{"): post_request.find("}") + 1
                ]
            )
    headers.pop("Content-Length", None)
    url_sample = request_line.strip().split(" ")[1]
    for target in targets:
        url = url_sample.replace("__target_locat_here__", str(target))
        try:
            port = url.split(":")[2].split("/")[0]
        except IndexError:
            if target.startswith("https://"):
                port = 443
            if target.startswith("http://"):
                port = 80
        response = __http_request_maker(
            req_type,
            url,
            headers,
            retries,
            time_sleep,
            timeout_sec,
            post_data_format,
            content_type,
            socks_proxy,
        )
        if isinstance(response, requests.models.Response):
            if rule_evaluator(response, condition):
                __log_into_file(thread_tmp_filename, "w", "0", language)
                sample_event["PORT"] = port
                event_parser(
                    message,
                    sample_event,
                    response,
                    payload,
                    log_in_file,
                    language,
                )
            output.append(
                {
                    "payload": payload,
                    "condition": condition,
                    "result": rule_evaluator(response, condition),
                    "response": response,
                }
            )
    return output


def request_without_data(
    request,
    req_type,
    retries,
    time_sleep,
    timeout_sec,
    payload,
    condition,
    output,
    sample_event,
    message,
    log_in_file,
    thread_tmp_filename,
    language,
    targets,
    ports,
    default_ports,
    socks_proxy,
):
    """
    this function extracts the data, headers and url for the requests other than POST type which is to be sent to
    the __http_request_maker function

    Args:
        request: the returned data from __http_requests_generator function
        req_type: GET, POST, PUT, DELETE or PATCH
        payload: the payload corresponding to which the request is made
        condition: the condition to be evaluated. eg: response.status_code == 200
        other args: retries, time_sleep, timeout_sec, output, sample_event,
                  message, log_in_file, thread_tmp_filename, language

    Returns:
         the list of outputs in the format
            [
                {
                    "payload": payload1,
                    "condition": condition1,
                    "result": rule_evaluator(response, condition),
                    "response": response1
                },......
            ]

    """
    request_line, headers_alone = request.split("\r\n", 1)
    headers = dict()
    try:
        for x in headers_alone.split("\r\n"):
            headers[x.split(":", 1)[0]] = x.split(":", 1)[1]
    except IndexError:
        headers[headers_alone.split(":", 1)[0]] = headers_alone.split(":", 1)[
            1
        ]
    clean_headers = {x.strip(): y.strip() for x, y in headers.items()}
    headers = clean_headers
    headers.pop("Content-Length", None)
    url_sample = request_line.strip().split(" ")[1]
    for target in targets:
        url = url_sample.replace("__target_locat_here__", str(target))
        try:
            port = url.split(":")[2].split("/")[0]
        except IndexError:
            if target.startswith("https://"):
                port = 443
            if target.startswith("http://"):
                port = 80
        response = __http_request_maker(
            req_type, url, headers, retries, time_sleep, timeout_sec
        )
        if isinstance(response, requests.models.Response):
            if rule_evaluator(response, condition):
                __log_into_file(thread_tmp_filename, "w", "0", language)
                sample_event["PORT"] = port
                event_parser(
                    message,
                    sample_event,
                    response,
                    payload,
                    log_in_file,
                    language,
                )
            output.append(
                {
                    "payload": payload,
                    "condition": condition,
                    "result": rule_evaluator(response, condition),
                    "response": response,
                }
            )
    return output


def rule_evaluator(response, condition):
    """
    this function evaluates conditions according to which it returns true or false

    Args:
        response:  output from __http_request_maker function
        condition: the condition to be evaluated. eg: response.status_code == 200

    Returns:
         true or false based on the condition

    """
    return eval(condition)


def sample_event_key_evaluator(response, payload, value):
    """
    this function returns the appropriate value for expressions in sample event by executing them

    Args:
    response: output from __http_request_maker function
    payload: the payload corresponding to the output
    value: the expression that needs to be evaluated

    Returns:
        the corresponding value by executing the expression
    """
    try:
        if value != "":
            exec ("global value1; value1 = " + value)
            value = value1
        return value
    except Exception as _:
        return value


def event_parser(
    message, sample_event, response, payload, log_in_file, language
):
    """
    this function is reponsible for logging events into the database and showing messages in the terminal

    Args:
        message: the sample message to be displayed in case of condition returning true
        sample_event: the sample event which is to be logged into the database
        other args: response, payload,log_in_file,language

    Returns:
        1
    """
    event = {}
    message = sample_event_key_evaluator(response, payload, message)
    for key, value in sample_event.items():
        event[key] = sample_event_key_evaluator(response, payload, value)
    info(message, log_in_file, "a", event, language)
    return 1


def __repeater(
    request_template,
    parameters,
    timeout_sec,
    thread_number,
    log_in_file,
    time_sleep,
    language,
    verbose_level,
    socks_proxy,
    retries,
    scan_id,
    scan_cmd,
    condition,
    thread_tmp_filename,
    sample_event,
    message,
    target,
    ports,
    default_ports,
    counter_message=None,
):
    """
    this function is the main repeater functions which determines the type of request, the content type and calls the
    appropriate funtion

    Args:
        request_template: the sample template of the request(to be supplied by the module)
        parameters: the payload in form of [[1,2,3], [1,2,3],...]
        condition: the condition to be evaluated. eg: response.status_code == 200
        sample_event: the template for the event that will be logged into the db
        message: the message that you want to display in the terminal when success
        counter_message: the message that you want to display if nothing is found
        target: the target to be attacked
        ports: the ports to be fuzzed
        default_ports: if user doesn't supply ports, these are to be fuzzed
        other args: retries, time_sleep, timeout_sec, thread_number, log_in_file, time_sleep, language,
                    verbose_level, socks_proxy, scan_id, scan_cmd, thread_tmp_filename

    Returns:
         Nothing

    """
    if counter_message is None:
        counter_message = messages(language, "fuzzer_no_response").format(
            sample_event["TYPE"]
        )
    __log_into_file(thread_tmp_filename, "w", "1", language)
    output = []
    request_text = request_template.replace("\r", "").replace("\n", "\r\n")
    content_type = ""
    request_type = ""
    if (
        request_text.rsplit()[0] == "POST" or request_text.rsplit()[0] == "PUT" or request_text.rsplit()[0] == "PATCH"
    ):
        request_type = "POST"
    elif (
        request_text.rsplit()[0] == "GET" or request_text.rsplit()[0] == "HEAD" or request_text.rsplit()[0] == "DELETE"
    ):
        request_type = "GET"
    req_type = request_text.rsplit()[0]
    threads = []
    keyboard_interrupt_flag = False
    requests_list = __http_requests_generator(request_text, parameters)
    targets = target_builder(target, ports, default_ports)
    for request in requests_list:
        if request_type == "POST":
            t = threading.Thread(
                target=request_with_data,
                args=(
                    request[0],
                    content_type,
                    req_type,
                    retries,
                    time_sleep,
                    timeout_sec,
                    request[1],
                    condition,
                    output,
                    sample_event,
                    message,
                    log_in_file,
                    thread_tmp_filename,
                    language,
                    targets,
                    ports,
                    default_ports,
                    socks_proxy,
                ),
            )
        elif request_type == "GET":
            t = threading.Thread(
                target=request_without_data,
                args=(
                    request[0],
                    req_type,
                    retries,
                    time_sleep,
                    timeout_sec,
                    request[1],
                    condition,
                    output,
                    sample_event,
                    message,
                    log_in_file,
                    thread_tmp_filename,
                    language,
                    targets,
                    ports,
                    default_ports,
                    socks_proxy,
                ),
            )
        threads.append(t)
        t.start()
        time.sleep(time_sleep)

        while 1:
            try:
                if threading.activeCount() >= thread_number:
                    time.sleep(0.01)
                else:
                    break
            except KeyboardInterrupt:
                keyboard_interrupt_flag = True
                break
        if keyboard_interrupt_flag:
            break

    # wait for threads
    kill_switch = 0
    kill_time = (
        int(timeout_sec / 0.1) if int(timeout_sec / 0.1) != 0 else 1
    )
    while 1:
        time.sleep(0.1)
        kill_switch += 1
        try:
            if threading.activeCount() == 1 or kill_switch == kill_time:
                break
        except KeyboardInterrupt:
            break
    thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
    if thread_write == 1 and verbose_level != 0:
        sample_event["DESCRIPTION"] = counter_message
        event_parser(
            message=counter_message,
            sample_event=sample_event,
            response=None,
            payload=None,
            log_in_file=log_in_file,
            language=language,
        )
    os.remove(thread_tmp_filename)

