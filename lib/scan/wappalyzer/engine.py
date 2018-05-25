import json
import re
import pkg_resources
import requests
from bs4 import BeautifulSoup
import threading
import string
import random
import time
import socket
import socks
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from core.compatible import version


def extra_requirements_dict():
    return {}


def _parse_webpage(target, timeout_sec, language, retries, socks_proxy, scan_cmd, scan_id):
    webpage = {}
    tries = 0
    if socks_proxy is not None:
        socks_version = socks.SOCKS5 if socks_proxy.startswith(
            'socks5://') else socks.SOCKS4
        socks_proxy = socks_proxy.rsplit('://')[1]
        if '@' in socks_proxy:
            socks_username = socks_proxy.rsplit(':')[0]
            socks_password = socks_proxy.rsplit(':')[1].rsplit('@')[0]
            socks.set_default_proxy(socks_version, str(socks_proxy.rsplit('@')[1].rsplit(':')[0]),
                                    int(socks_proxy.rsplit(':')[-1]), username=socks_username,
                                    password=socks_password)
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
        else:
            socks.set_default_proxy(socks_version, str(
                socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
    try:
        if timeout_sec is not None:
            response = requests.get(target, timeout=timeout_sec)
        else:
            response = requests.get(target)
        webpage['url'] = response.url
        webpage['headers'] = response.headers
        webpage['response'] = response.text
        webpage['html'] = BeautifulSoup(response.text, 'html.parser')
        webpage['scripts'] = [script['src']
                              for script in webpage['html'].findAll('script', src=True)]
        webpage['metatags'] = {meta['name'].lower(): meta['content']
                               for meta in webpage['html'].findAll('meta', attrs=dict(name=True, content=True))}
        return webpage
    except:
        tries += 1
        if tries >= retries:
            info(messages(language, "no_response"))
            return


def _prepare_app(app):

    for key in ['url', 'html', 'script', 'implies']:
        try:
            value = app[key]
        except KeyError:
            app[key] = []
        else:
            if not isinstance(value, list):
                app[key] = [value]

    for key in ['headers', 'meta']:
        try:
            value = app[key]
        except KeyError:
            app[key] = {}

    obj = app['meta']
    if not isinstance(obj, dict):
        app['meta'] = {'generator': obj}

    for key in ['headers', 'meta']:
        obj = app[key]
        app[key] = {k.lower(): v for k, v in obj.items()}

    for key in ['url', 'html', 'script']:
        app[key] = [_prepare_pattern(pattern) for pattern in app[key]]

    for key in ['headers', 'meta']:
        obj = app[key]
        for name, pattern in obj.items():
            obj[name] = _prepare_pattern(obj[name])


def _prepare_pattern(pattern):
    regex, _, rest = pattern.partition('\\;')
    try:
        return re.compile(regex, re.I)
    except re.error as e:
        # regex that never matches:
        # http://stackoverflow.com/a/1845097/413622
        return re.compile(r'(?!x)x')


def _has_app(app, webpage):
    try:
        for regex in app['url']:
            if regex.search(webpage['url']):
                return True
        for name, regex in app['headers'].items():
            if name in webpage['headers']:
                content = webpage['headers'][name]
                if regex.search(content):
                    return True
        for regex in app['script']:
            for script in webpage['scripts']:
                if regex.search(script):
                    return True
        for name, regex in app['meta'].items():
            if name in webpage['metatags']:
                content = webpage['metatags'][name]
                if regex.search(content):
                    return True
        for regex in app['html']:
            if regex.search(webpage['response']):
                return True
    except:
        pass


def _get_implied_apps(detected_apps, apps1):

    def __get_implied_apps(detect, apps):
        _implied_apps = set()
        for detected in detect:
            try:
                _implied_apps.update(set(apps[detected]['implies']))
            except KeyError:
                pass
        return _implied_apps

    implied_apps = __get_implied_apps(detected_apps, apps1)
    all_implied_apps = set()

    while not all_implied_apps.issuperset(implied_apps):
        all_implied_apps.update(implied_apps)
        implied_apps = __get_implied_apps(all_implied_apps, apps1)

    return all_implied_apps


def analyze(target, timeout_sec, log_in_file, language,
            time_sleep, thread_tmp_filename, retries,
            socks_proxy, scan_id, scan_cmd):
    webpage = _parse_webpage(
        target, timeout_sec, language, retries, socks_proxy, scan_cmd, scan_id)
    obj = json.loads(pkg_resources.resource_string(__name__, "apps.json").decode()
                     if version() is 3 else pkg_resources.resource_string(__name__, "apps.json"))
    apps = obj['apps']
    detected = []
    for app_name, app in apps.items():
        _prepare_app(app)
        if _has_app(app, webpage):
            detected.append(app_name)
    detected = set(detected).union(_get_implied_apps(detected, apps))
    category_wise = {}
    for app_name in detected:
        cats = apps[app_name]['cats']
        for cat in cats:
            category_wise[app_name] = obj['categories'][str(cat)]['name']
    inv_map = {}
    for k, v in category_wise.items():
        inv_map[v] = inv_map.get(v, [])
        inv_map[v].append(k)
    for x in inv_map.items():
        info(messages(language, "category_framework").format(
            x[0], ', '.join(x[1])))
        data = json.dumps(
            {'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'wappalyzer_scan',
             'DESCRIPTION': x[0] + ': ' + ', '.join(x[1]), 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
             'SCAN_CMD': scan_cmd})
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        __log_into_file(log_in_file, 'a', data, language)


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(
            target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
        threads = []
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        total_req = 8000
        if target_type(target) != "HTTP":
            target = 'http://' + target
        t = threading.Thread(target=analyze,
                             args=(
                                 target, timeout_sec, log_in_file, language,
                                 time_sleep, thread_tmp_filename, retries,
                                 socks_proxy, scan_id, scan_cmd))
        threads.append(t)
        t.start()
        trying += 1
        if verbose_level > 3:
            info(messages(language, "trying_message").format(trying, total_req, num, total, target_to_host(target),
                                                             "", 'dir_scan'))
        while 1:
            try:
                if threading.activeCount() >= thread_number:
                    time.sleep(0.01)
                else:
                    break
            except KeyboardInterrupt:
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
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write is 1:
            info(messages(language, "nothing_found").format(
                target, "wappalyzer_scan"))
            if verbose_level is not 0:
                data = json.dumps({'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'wappalyzer_scan',
                                   'DESCRIPTION': messages(language, "not_found"), 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                                   'SCAN_CMD': scan_cmd})
                __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, "input_target_error").format(
            'wappalyzer_scan', target))
