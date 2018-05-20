#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import json
import requests
import itertools
import threading
from mimetools import Message
from StringIO import StringIO


def post_data_parser(post_data):
    post_data_json = {}
    for parameter in post_data.rsplit("&"):
        post_data_json[parameter.rsplit("=")[0]] = parameter.rsplit("=")[1]
    return post_data_json


def __http_requests_generator(request_template, parameters):
    for payload in itertools.product(*parameters):
        yield request_template.format(*payload)


def __http_request_maker(req_type, url, headers, retries, time_sleep, timeout_sec=None, data=None, content_type=None):
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
        except Exception as e:
            print e
            exit += 1
            if exit is retries:
                break
            else:
                time.sleep(time_sleep)
                continue
    return r


def prepare_post_request(post_request, content_type, req_type, retries, time_sleep, timeout_sec):
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
    return __http_request_maker(req_type, url, headers, retries, time_sleep, timeout_sec,
                                   post_data_format, content_type)


def other_request(request, req_type, retries, time_sleep, timeout_sec):
    request_line, headers_alone = request.split('\r\n', 1)
    headers = Message(StringIO(headers_alone)).dict
    url = request_line.strip().split(' ')[1]
    headers.pop("Content-Length", None)
    return __http_request_maker(req_type, url, headers, retries, time_sleep, timeout_sec)


def __repeater(request_template, parameters, timeout_sec, thread_number, log_in_file, time_sleep, language,
                   verbose_level, socks_proxy, retries, scan_id, scan_cmd):
        request_text = request_template.replace("\r", "").replace("\n", "\r\n")
        content_type = ""
        if request_text.rsplit()[0] == "POST" or request_text.rsplit()[0] == "PUT" or \
                request_text.rsplit()[0] == "PATCH":
            req_type = request_text.rsplit()[0]
            requests_list = __http_requests_generator(request_text, parameters)
            for total_request, _ in enumerate(__http_requests_generator(request_text, parameters)):
                pass
            total_request += 1
            n = 0
            data = {}
            threads = []
            for post_request in requests_list:
                t = threading.Thread(target=prepare_post_request,
                                     args=(post_request, content_type, req_type, retries,
                                           time_sleep, timeout_sec))
                threads.append(t)
                t.start()
                time.sleep(time_sleep)
            return 1
        elif request_text.rsplit()[0] == "GET" or request_text.rsplit()[0] == "HEAD" or \
                request_text.rsplit()[0] == "DELETE":
            req_type = request_text.rsplit()[0]
            threads = []
            requests_list = __http_requests_generator(request_text, parameters)
            for total_request, _ in enumerate(__http_requests_generator(request_text, parameters)):
                pass
            total_request += 1
            for request in requests_list:
                t = threading.Thread(target=other_request,
                                     args=(
                                         request, req_type, retries, time_sleep, timeout_sec))
                threads.append(t)
                t.start()
                time.sleep(time_sleep)
            return 1
