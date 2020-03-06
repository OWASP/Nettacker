import time
import requests
import socks
import socket
import json
import re
from bs4 import BeautifulSoup as BS
from core._time import now
from core.alert import *
from core.targets import target_to_host
from core.targets import target_type
from core.log import __log_into_file
from lib.socks_resolver.engine import getaddrinfo


def extra_requirement_dict():
    return {}


def search_platform(target, search):
    '''
    Args:
        target = Domain
        search=search engines for parsing query
    Returns:
        the search request url dictionary
    '''
    if search == 'google':
        url = 'https://www.google.com/search?num=50&hl=en&meta=&q='
    elif search == 'bing':
        url = 'http://www.bing.com/search?count=50&setlang=en-us&q='
    elif search == 'yahoo':
        url = 'https://search.yahoo.com/search?&fr=yfp-t-152&n=10&p='
    return {
        'search_'+search: url + target,
        'linkedin_url': url + 'site:linkedin.com/in' + target,
        'twitter_url': url + 'site:twitter.com ' + target,
        'github_url': url + 'site:github.com ' + target
    }


def start(target, users, passwds, ports, timeout_sec, thread_number, num,
          total, log_in_file, time_sleep, language, verbose_level, socks_proxy,
          retries, methods_args, scan_id, scan_cmd):  # Main function
    if (target_type(target) != 'SINGLE_IPv4' or
            target_type(target) != 'DOMAIN' or
            target_type(target) != 'HTTP' or
            target_type != 'SINGLE_IPv6'):  # output format
        time.sleep(time_sleep)
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith(
                'socks5://') else socks.SOCKS4
            socks_proxy = socks_proxy.rsplit('://')[1]
            if '@' in socks_proxy:
                socks_username = socks_proxy.rsplit(':')[0]
                socks_password = socks_proxy.rsplit(':')[1].rsplit('@')[0]
                socks.set_default_proxy(socks_version,
                                        str(socks_proxy.rsplit('@')[1]
                                            .rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[-1]),
                                        username=socks_username,
                                        password=socks_password)
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
            else:
                socks.set_default_proxy(socks_version,
                                        str(socks_proxy.rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        # set user agent
        headers = {"User-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                                 "AppleWebKit/537.36 (KHTML, like Gecko) " +
                                 "Chrome/74.0.3729.169 Safari/537.36",
                   "Accept": "text/javascript, text/html, " +
                             "application/xml, text/xml, */*",
                   "Accept-Language": "en-US,en;q=0.5"
                   }
        # info(messages(language,"done"))
        # main harvest function
        mails = []   # mail list empty
        search_engines = {'google': '.st', 'bing': '.b_caption p',
                          'yahoo': 'lh-16'}
        # this search engines have class which contain metadata
        if target_type(target) == 'HTTP':   # changing http target into domain
            target = target_to_host(target)
        if target_type(target) == 'DOMAIN':
            target = target.replace('www.', '')
            for engine in search_engines:
                links = search_platform(target, engine)
                info(messages(language, "waiting").format(engine))
                for platform in links:
                    scrap = requests.get(links[platform], headers=headers)
                    if scrap.status_code == 200:
                        info(messages(language, "checking").format(platform))
                    parse = BS(scrap.text, 'lxml')
                    results = parse.select(search_engines[engine])
                    for result in results:
                        mail_pattern = re.compile(
                            '[a-zA-Z0-9.\-_+#~!$&\',;=:]+' +
                            '@' +
                            '[a-zA-Z0-9.-]*' + target)
                        information = mail_pattern.findall(result.text)
                        for item in information:
                            if item.endswith(target) and item not in mails:
                                mails.append(item)
        for mail in mails:
            try:
                if verobose_level > 3:
                    info(messages(language, "done"))
            except NameError:
                verbose_level = 0
                # info(messages(language,"choose_scan_method").format(mail))
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '',
                               'PORT': '', 'TYPE': 'mail_id_harvest_scan',
                               'DESCRIPTION': mail, 'TIME': now(),
                               'CATEGORY': "scan", 'SCAN_ID': scan_id,
                               'SCAN_CMD': scan_cmd}) + "\n"
            __log_into_file(log_in_file, 'a', data, language)
        if verbose_level is not 0:
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '',
                               'PORT': '', 'TYPE': 'mail_id_harvest_scan',
                               'DESCRIPTION':
                                   messages(language, "domain_found")
                                   .format(len(mails), ", ".join(mails)
                                           if len(mails) > 0 else "None"),
                               'TIME': now(), 'CATEGORY': "scan",
                               'SCAN_ID': scan_id,
                               'SCAN_CMD': scan_cmd}) + "\n"
            __log_into_file(log_in_file, 'a', data, language)
    else:
        warn(messages(language, "input_target_error")
             .format('mail_id_harvest_scan', target))

