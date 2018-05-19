#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import requests
import itertools
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


def __repeater(request_template, parameters, timeout_sec, thread_number, log_in_file, time_sleep, language,
                   verbose_level, socks_proxy, retries, scan_id, scan_cmd):
        request_text = request_template.replace("\r", "").replace("\n", "\r\n")

        if request_text.rsplit()[0] == "POST" or request_text.rsplit()[0] == "PUT" or \
                request_text.rsplit()[0] == "PATCH":
            req_type = request_text.rsplit()[0]
            requests_list = __http_requests_generator(request_text, parameters)
            for total_request, _ in enumerate(__http_requests_generator(request_text, parameters)):
                pass
            total_request += 1
            n = 0
            data = {}
            for post_request in requests_list:
                n += 1
                print("request", n, "from", total_request)
                request_line, headers_alone = post_request.split('\r\n', 1)
                headers = Message(StringIO(headers_alone)).dict
                post_data_format = post_data_parser(post_request.split('\r\n')[-1])
                url = request_line.strip().split(' ')[1]
                headers.pop("Content-Length", None)
                exit = 0
                while True:
                    try:
                        if timeout_sec is not None:
                            if req_type == "POST":
                                r = requests.post(url=url, headers=headers, data=post_data_format)
                            elif req_type == "PUT":
                                r = requests.put(url=url, headers=headers, data=post_data_format)
                            elif req_type == "PATCH":
                                r = requests.patch(url=url, headers=headers, data=post_data_format)
                            data[n] = r
                        else:
                            if req_type == "POST":
                                r = requests.post(url=url, headers=headers, data=post_data_format, timeout=timeout_sec)
                            elif req_type == "PUT":
                                r = requests.put(url=url, headers=headers, data=post_data_format, timeout=timeout_sec)
                            elif req_type == "PATCH":
                                r = requests.patch(url=url, headers=headers, data=post_data_format, timeout=timeout_sec)
                            data[n] = r
                        break
                    except Exception as _:
                        exit += 1
                        if exit is retries:
                            break
                        else:
                            time.sleep(time_sleep)
                            continue
            return data

        elif request_text.rsplit()[0] == "GET" or request_text.rsplit()[0] == "HEAD" or \
                request_text.rsplit()[0] == "DELETE":
            req_type = request_text.rsplit()[0]
            print(req_type)
            requests_list = __http_requests_generator(request_text, parameters)
            for total_request, _ in enumerate(__http_requests_generator(request_text, parameters)):
                pass
            total_request += 1
            n = 0
            data = {}
            for request in requests_list:
                n += 1
                print("request", n, "from", total_request)
                request_line, headers_alone = request.split('\r\n', 1)
                headers = Message(StringIO(headers_alone)).dict
                url = request_line.strip().split(' ')[1]
                print url
                headers.pop("Content-Length", None)
                exit = 0
                while True:
                    try:
                        if timeout_sec is not None:
                            if req_type == "GET":
                                r = requests.get(url=url, headers=headers)
                            elif req_type == "HEAD":
                                r = requests.head(url=url, headers=headers)
                            elif req_type == "DELETE":
                                r = requests.delete(url=url, headers=headers)
                            data[n] = r
                        else:
                            if req_type == "GET":
                                r = requests.get(url=url, headers=headers, timeout=timeout_sec)
                            elif req_type == "HEAD":
                                r = requests.head(url=url, headers=headers, timeout=timeout_sec)
                            elif req_type == "DELETE":
                                r = requests.delete(url=url, headers=headers, timeout=timeout_sec)
                            data[n] = r
                        break
                    except Exception as e:
                        print e
                        exit += 1
                        if exit is retries:
                            break
                        else:
                            time.sleep(time_sleep)
                            continue
            print data
