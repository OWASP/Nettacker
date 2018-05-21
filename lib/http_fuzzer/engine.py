#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import json
import requests
import itertools
import threading
from mimetools import Message
from StringIO import StringIO

output = {}


def post_data_parser(post_data):
    """
    this function parses the post request format when the content type is application/x-www-form-urlencoded. It converts
    the post request parameters to a json dictionary that can be passed to requests library as data

    Args:
        post_data

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
        yield request_template.format(*payload),payload


def __http_request_maker(req_type, url, headers, retries, time_sleep, timeout_sec=None, data=None, content_type=None):
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
    exit = 0
    r=None
    while True:
        try:
            if timeout_sec is None:
                if req_type == "POST":
                    if content_type == 'application/data':
                        r = requests.post(url=url, headers=headers, data=data)
                    elif content_type == 'application/json':
                        r = requests.post(url=url, headers=headers, json=data)
                elif req_type == "PUT":
                    if content_type == 'application/data':
                        r = requests.put(url=url, headers=headers, data=data)
                    elif content_type == 'application/json':
                        r = requests.put(url=url, headers=headers, json=json)
                elif req_type == "PATCH":
                    if content_type == 'application/data':
                        r = requests.patch(url=url, headers=headers, data=data)
                    elif content_type == 'application/json':
                        r = requests.patch(url=url, headers=headers, json=data)
                elif req_type == "GET":
                    r = requests.get(url=url, headers=headers)
                elif req_type == "HEAD":
                    r = requests.head(url=url, headers=headers)
                elif req_type == "DELETE":
                    r = requests.delete(url=url, headers=headers)
            else:
                if req_type == "POST":
                    if content_type == 'application/data':
                        r = requests.post(url=url, headers=headers, data=data, timeout=timeout_sec)
                    elif content_type == 'application/json':
                        r = requests.post(url=url, headers=headers, json=data, timeout=timeout_sec)
                elif req_type == "PUT":
                    if content_type == 'application/data':
                        r = requests.put(url=url, headers=headers, data=data, timeout=timeout_sec)
                    elif content_type == 'application/json':
                        r = requests.put(url=url, headers=headers, json=data, timeout=timeout_sec)
                elif req_type == "PATCH":
                    if content_type == 'application/data':
                        r = requests.patch(url=url, headers=headers, data=data, timeout=timeout_sec)
                    elif content_type == 'application/json':
                        r = requests.patch(url=url, headers=headers, json=data, timeout=timeout_sec)
                elif req_type == "GET":
                    r = requests.get(url=url, headers=headers, timeout=timeout_sec)
                elif req_type == "HEAD":
                    r = requests.head(url=url, headers=headers, timeout=timeout_sec)
                elif req_type == "DELETE":
                    r = requests.delete(url=url, headers=headers, timeout=timeout_sec)
            break
        except Exception as _:
            exit += 1
            if exit is retries:
                return 0
                break
            else:
                time.sleep(time_sleep)
                continue
    return r


def prepare_post_request(post_request, content_type, req_type, retries, time_sleep, timeout_sec, payload, rule_type, condition):
    """
    this function extracts the data, headers and url for the POST type request which is to be sent to
    the __http_request_maker function

    Args:
        post_request: the returned data from __http_requests_generator function
        req_type: GET, POST, PUT, DELETE or PATCH
        content_type: application/json or application/x-www-form-urlencoded
        payload: the payload corresponding to which the request is made
        rule_type: the type of parameter you want to check conditions on. eg: status_code, json, etc.
        condition: the condition to be evaluated. eg: response.status_code == 200
        other args: retries, time_sleep, timeout_sec

    Returns:
         the dictionary of outputs in the format
            {
                payload1: corresponding output,
                ...
            }

    """
    request_line, headers_alone = post_request.split('\r\n', 1)
    headers = Message(StringIO(headers_alone)).dict
    url = request_line.strip().split(' ')[1]
    if "content-type" in headers:
        content_type = headers['content-type']
        if content_type == 'application/x-www-form-urlencoded':
            post_data_format = post_data_parser(post_request.split('\r\n')[-1])
        elif content_type == 'application/json':
            post_data_format = json.loads(post_request[post_request.find('{'):post_request.find('}') + 1])
    headers.pop("Content-Length", None)
    response = __http_request_maker(req_type, url, headers, retries, time_sleep, timeout_sec,
                                   post_data_format, content_type)
    output[payload] = rule_evaluator(response, rule_type, condition)
    return output


def other_request(request, req_type, retries, time_sleep, timeout_sec, payload, rule_type, condition):
    """
    this function extracts the data, headers and url for the requests other than POST type which is to be sent to
    the __http_request_maker function

    Args:
        request: the returned data from __http_requests_generator function
        req_type: GET, POST, PUT, DELETE or PATCH
        payload: the payload corresponding to which the request is made
        rule_type: the type of parameter you want to check conditions on. eg: status_code, json, etc.
        condition: the condition to be evaluated. eg: response.status_code == 200
        other args: retries, time_sleep, timeout_sec

    Returns:
         the dictionary of outputs in the format
            {
                payload1: corresponding output,
                ...
            }

    """
    request_line, headers_alone = request.split('\r\n', 1)
    headers = Message(StringIO(headers_alone)).dict
    url = request_line.strip().split(' ')[1]
    headers.pop("Content-Length", None)
    response = __http_request_maker(req_type, url, headers, retries, time_sleep, timeout_sec)
    output[payload] = rule_evaluator(response, rule_type, condition)
    return output


def rule_evaluator(response, rule_type, condition):
    """
    this function evaluates conditions according to which it returns true or false

    Args:
        response:  output from __http_request_maker function
        rule_type: the type of parameter you want to check conditions on. eg: status_code, json, etc.
        condition: the condition to be evaluated. eg: response.status_code == 200

    Returns:
         true or false based on the condition

    """
    return eval(condition)


def __repeater(request_template, parameters, timeout_sec, thread_number, log_in_file, time_sleep, language,
                   verbose_level, socks_proxy, retries, scan_id, scan_cmd, rule_type, condition):
    """
    this function is the main repeater functions which determines the type of request, the content type and calls the
    appropriate funtion

    Args:
        request_template: the sample template of the request(to be supplied by the module)
        parameters: the payload in form of [[1,2,3], [1,2,3],...]
        rule_type: the type of parameter you want to check conditions on. eg: status_code, json, etc.
        condition: the condition to be evaluated. eg: response.status_code == 200
        other args: retries, time_sleep, timeout_sec, thread_number, log_in_file, time_sleep, language,
                   verbose_level, socks_proxy, scan_id, scan_cmd

    Returns:
         1

    """
    request_text = request_template.replace("\r", "").replace("\n", "\r\n")
    content_type = ""
    request_type = ""
    if request_text.rsplit()[0] == "POST" or request_text.rsplit()[0] == "PUT" or \
            request_text.rsplit()[0] == "PATCH":
        request_type = "POST"
    elif request_text.rsplit()[0] == "GET" or request_text.rsplit()[0] == "HEAD" or \
         request_text.rsplit()[0] == "DELETE":
        request_type = "GET"
    req_type = request_text.rsplit()[0]
    threads = []
    keyboard_interrupt_flag = False
    requests_list = __http_requests_generator(request_text, parameters)
    for request in requests_list:
        if request_type == "POST":
            t = threading.Thread(target=prepare_post_request,
                                 args=(request[0], content_type, req_type, retries,
                                       time_sleep, timeout_sec, request[1], rule_type, condition))
        elif request_type == "GET":
            t = threading.Thread(target=other_request,
                                 args=(request[0], req_type, retries, time_sleep, timeout_sec, request[1],
                                       rule_type, condition))
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
    kill_time = int(
        timeout_sec / 0.1) if int(timeout_sec / 0.1) is not 0 else 1
    while 1:
        time.sleep(0.1)
        kill_switch += 1
        try:
            if threading.activeCount() is 1 or kill_switch is kill_time:
                break
        except KeyboardInterrupt:
            break
    return 1