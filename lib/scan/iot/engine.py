import re
import ssl
import sys
import json
import base64
import urllib2
import threading
from core.alert import *
from core._time import now
from subprocess import Popen, PIPE
from core.targets import target_type
from core.log import __log_into_file

devs = {};
ipList = []
httpPort = 80
debug = 0
scanid = ''
scancmd = ''
lang = ''
loginfile = ''
devCfgUrl = ''

numOfIps = 0

TIME_OUT = 15

def readDevices():
    global devs
    if(devCfgUrl != ""):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        req = urllib2.Request(devCfgUrl, headers={ 'User-Agent': 'Mozilla/5.0' })
        req.get_method = lambda: 'GET'
        try:
            buff = urllib2.urlopen(req, context=context, timeout=TIME_OUT).read()
        except:
            error("Faild to read config file from: " + str(devCfgUrl))
    else:
        with open("lib/scan/iot/devices.cfg", "r") as f:
            buff = f.read(0x1000000)
    devs = json.loads(buff)
    #print json.dumps(devs, indent=4)


def search4devType(body, headers):
    for e in devs.keys():
        p = devs[e]['devTypePattern']
        if p[0][0] == "header":
            try:
                tmp = headers[p[0][1]]
            except:
                tmp = ""
        elif p[0][0] == "body":
            if p[0][1] == "":
                tmp = body
            else:
                pattern = "<" + str(p[0][1]) + ">(.*?)</" + str(p[0][1]) + ">"
                match = re.search(pattern, body)
                if match:
                    tmp = match.group(1) if match else ''
                else:
                    continue
        p = devs[e]['devTypePattern'][1]
        tlen = len(p)
        if p[0] == "==":
            if tmp.decode('utf-8') == p[1]:
                return e
        elif re.match(r'^regex', p[0]):
            for i in range(1, tlen + 1):
                try:
                    pattern = p[i]
                    match = re.search(pattern, tmp)
                    if not match:
                        break
                except:
                    pass
            if i == tlen:
                return e
        elif p[0] == "substr":
            try: 
                tmp = tmp.decode('utf-8')
            except:
                pass
            try:
                if tmp.index(p[1]) >= 0:
                    return e
            except ValueError:
                pass
    return ""

def getRefreshUrl(prevUrl, body):
    newUrl = ''
    tmpBody = body
    while re.match('\<META\s+[^\>]*url=(.*?)>', tmpBody, re.IGNORECASE):
        tmpBody = match.string[match.end():]
        tmp = match.group()
        if re.match('^[\"\'](.*?)[\"\']', tmp):
            newUrl = match.group()
            break
        elif re.match('^(.*?)[\>\"\s]', tmp):
            newUrl = match.group()
            break
    if newUrl != "" and newUrl != prevUrl:
        return newUrl
    else:
        return ""


def match(body):
    title = ''
    match = re.search('<title>(.*?)<\/title>', body)
    if not match:
        return ""
    title = match.group()
    for e in devs.keys():
        patterns = devs[e]['devTypePattern']
        isMatch = 1
        for f in patterns:
            if not re.match(f, title):
                isMatch = 0
                break
        if isMatch:
            return e
        
    return ""

def search4login(ctx, body):
    devType = match(body)
    if devType == "":
        error("didnot find devType for " + ctx[ip])
        return
    pattern = devs[devType]['loginUrlPattern']
    match = re.search(pattern, body)
    if match:
        return match.group()
    return ""


def substitute(postdata, extracetdData):
    mystr = postdata
    p = extracetdData
    ret = ''
    while(re.match(r'\$(\d+)', mystr)):
        match = re.search(r'\$(\d+)', mystr)
        ret += match.string[:match.start()] + p[match.group() - 1]
        mystr = match.string[match.end():]

    ret += mystr
    return ret

def check_login(ctx, body, port):
    headersss = {}
    url = composeURL(ctx, port)
    dev = ctx['dev']
    if dev['auth'][0] == "basic":
        if dev['auth'][1] == "":
            def http_get(url):
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  

                req = urllib2.Request(url, headers={ 'User-Agent': 'Mozilla/5.0' })
                req.get_method = lambda: 'GET'
                
                try:
                    res = urllib2.urlopen(req, context=context, timeout=TIME_OUT)
                    body = res.read()
                    headers = {"Status":res.getcode(), "location":res.geturl(), "Content-Length":len(body)}
                    for hdr in res.info():
                        headers.update({hdr:res.info()[hdr]})
                except urllib2.HTTPError as e:
                    body = e.read()
                    headers = {"Status":e.getcode(), "location":e.geturl(), "Content-Length":len(body)}
                    for hdr in e.info():
                        headers.update({hdr:e.info()[hdr]})
                except urllib2.URLError as e:
                    body = ''
                    headers = {"Status":595, "location":url, "Content-Length":len(body)}

                def sub(headers):
                    status = int(headers[1]['Status'])
                    if int(status) == 200:
                        resp = "device " + ctx['ip'] + " is of type " + ctx['devType'] + " still has default password"
                        info(resp)
                        data = json.dumps({'HOST': ctx['ip'], 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                           'TYPE': 'iot_scan', 'DESCRIPTION': str(resp),
                           'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scanid, 'SCAN_CMD': scancmd}) + "\n"
                    else:
                        resp = "device " + ctx['ip'] + " is of type " + ctx['devType'] + " has changed password"
                        info(resp)
                        data = json.dumps({'HOST': ctx['ip'], 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                           'TYPE': 'iot_scan', 'DESCRIPTION': str(resp),
                           'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scanid, 'SCAN_CMD': scancmd}) + "\n"
                    __log_into_file(loginfile, 'a', data, lang)
                    return
                sub(headers)                
            http_get(url)
        tmp = "Basic " + base64.encodestring(dev['auth'][1])
        tmp.strip()
        headersss.update({"Authorization": tmp})
    elif dev['auth'][0] == "form":
        subType = dev['auth'][1]
        postdata = dev['auth'][2]
        try:
            dev['extractFormData']
            for e in dev['extractFormData']:
                match = re.search(e, body)
                if math:
                    try:
                        ctx['extractedData']
                    except:
                        ctx['extractedData'] = []
                    ctx['extractedData'].append(match.group(1))
        except:
            pass
        if re.match(r'^sub', subType):
            subType = ""
            postdata = substitute(postdata, ctx['extractedData'])
        if subType == "":
            def http_post(url, postdata, dev):
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  

                req = urllib2.Request(url, headers={ 'User-Agent': 'Mozilla/5.0' }, data=postdata)
                req.get_method = lambda: 'POST'
                try:
                    res = urllib2.urlopen(req, context=context, timeout=TIME_OUT)
                    body = res.read()
                    headers = {"Status":res.getcode(), "location":res.geturl(), "Content-Length":len(body)}
                    for hdr in res.info():
                        headers.update({hdr:res.info()[hdr]})
                except urllib2.HTTPError as e:
                    body = e.read()
                    headers = {"Status":e.getcode(), "location":e.geturl(), "Content-Length":len(body)}
                    for hdr in e.info():
                        headers.update({hdr:e.info()[hdr]})
                except urllib2.URLError as e:
                    body = ''
                    headers = {"Status":595, "location":url, "Content-Length":len(body)}
            
                def sub1(body, headers, dev):
                    if dev['auth'][3] == "body":
                        if dev['auth'][4] == "regex":
                            pattern = dev['auth'][5]
                            if re.match(pattern, body):
                                resp = "device " + ctx['ip'] + " is of type " + ctx['devType'] + " still has default password"
                                info(resp)
                                data = json.dumps({'HOST': ctx['ip'], 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                                   'TYPE': 'iot_scan', 'DESCRIPTION': str(resp),
                                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scanid, 'SCAN_CMD': scancmd}) + "\n"
                            else:
                                resp = "device " + ctx['ip'] + " of type " + ctx['devType'] + " has changed password"
                                info(resp)
                                data = json.dumps({'HOST': ctx['ip'], 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                                   'TYPE': 'iot_scan', 'DESCRIPTION': str(resp),
                                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scanid, 'SCAN_CMD': scancmd}) + "\n"
                            __log_into_file(loginfile, 'a', data, lang)
                            return
                        elif dev['auth'][4] == "!substr":
                            body = body.decode('utf-8')
                            if body.index(dev['auth'])[5] < 0:
                                resp = "device " + ctx['ip'] + " is of type " + ctx['devType'] + " still has default password"
                                info(resp)
                                data = json.dumps({'HOST': ctx['ip'], 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                                   'TYPE': 'iot_scan', 'DESCRIPTION': str(resp),
                                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scanid, 'SCAN_CMD': scancmd}) + "\n"
                            else:
                                resp = "device " + ctx['ip'] + " of type " + ctx['devType'] + " has changed password"
                                info(resp)
                                data = json.dumps({'HOST': ctx['ip'], 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                                   'TYPE': 'iot_scan', 'DESCRIPTION': str(resp),
                                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scanid, 'SCAN_CMD': scancmd}) + "\n"
                            __log_into_file(loginfile, 'a', data, lang)
                            return
                sub1(body, headers, dev)
            http_post(url, postdata, dev)
    if debug:
        warn("checking login on " + url)
    def http_get1(url, hdrs, ctx):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        req = urllib2.Request(url, headers=hdrs)
        req.get_method = lambda: 'GET'
        try:
            res = urllib2.urlopen(req, context=context, timeout=TIME_OUT)
            body = res.read()
            headers = {"Status":res.getcode(), "location":res.geturl(), "Content-Length":len(body)}
            for hdr in res.info():
                headers.update({hdr:res.info()[hdr]})
        except urllib2.HTTPError as err:
            body = err.read()
            headers = {"Status":err.getcode(), "location":err.geturl(), "Content-Length":len(body)}
            for hdr in err.info():
                headers.update({hdr:err.info()[hdr]})
        except urllib2.URLError as err:
            body = ''
            headers = {"Status":595, "location":url, "Content-Length":len(body)}

        def sub2(headers, ctx):
            status = int(headers['Status'])
            if debug:
                print "check_login status=" + str(status)
            data = ''
            if int(status) == 200:
                if ctx['dev']['auth'][0] == "basic":
                    resp = "device " + ctx['ip'] + " is of type " + ctx['devType'] + " still has default password"
                    info(resp)
                    data = json.dumps({'HOST': ctx['ip'], 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                                   'TYPE': 'iot_scan', 'DESCRIPTION': str(resp),
                                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scanid, 'SCAN_CMD': scancmd}) + "\n"
                elif ctx['dev']['auth'][0] == "expect200":
                    resp = "device " + ctx['ip'] + " is of type " + ctx['devType'] + "does not have any password"
                    info(resp)
                    data = json.dumps({'HOST': ctx['ip'], 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                                   'TYPE': 'iot_scan', 'DESCRIPTION': str(resp),
                                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scanid, 'SCAN_CMD': scancmd}) + "\n"
            elif int(status) == 301 or int(status) == 302:
                resp = "device " + ctx['ip'] + " is of type " + ctx['devType'] + " still has default password"
                info(resp)
                data = json.dumps({'HOST': ctx['ip'], 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                                   'TYPE': 'iot_scan', 'DESCRIPTION': str(resp),
                                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scanid, 'SCAN_CMD': scancmd}) + "\n"
            elif int(status) == 401 and ctx['dev']['auth'][0] == "basic":
                resp = "device " + ctx['ip'] + " is of type " + ctx['devType'] + " has changed password"
                info(resp)
                data = json.dumps({'HOST': ctx['ip'], 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                                   'TYPE': 'iot_scan', 'DESCRIPTION': str(resp),
                                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scanid, 'SCAN_CMD': scancmd}) + "\n"
            else:
                resp = "device " + ctx['ip'] + ": unexpected resp code " + str(status)
                error(resp)
                data = json.dumps({'HOST': ctx['ip'], 'USERNAME': '', 'PASSWORD': '', 'PORT': '',
                                                   'TYPE': 'iot_scan', 'DESCRIPTION': str(resp),
                                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scanid, 'SCAN_CMD': scancmd}) + "\n"
            __log_into_file(loginfile, 'a', data, lang)
            return
        sub2(headers, ctx)
    http_get1(url, headersss, ctx)


def gotoCheckLogin(ctx, url, body, port):
    try:
        pattern = ctx['dev']['loginUrlPattern']
        match = re.search(pattern, body)
        if match:
            ur = match.group(1) if match else ''
            ctx.update({'url':ur})
            return check_login(ctx, body, port)            
    except:
        tmp = ctx['dev']['nextUrl']
        if tmp[0] == "string":
            if tmp[1] != "":
                ctx.update({'url':tmp[1]})
            else:
                ctx.update({'url':url})
    check_login(ctx, body, port)



def check(ctx, port):
    url = composeURL(ctx, port)
    if (ctx['stage'] == "initialClickLoginPage"):
        return check_init_login(ctx) 
    def http_get(url, ctx, port):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        req = urllib2.Request(url, headers={ 'User-Agent': 'Mozilla/5.0' })
        req.get_method = lambda: 'GET'
        try:
            res = urllib2.urlopen(req, context=context, timeout=TIME_OUT)
            body = res.read()
            headers = {"Status":res.getcode(), "location":res.geturl(), "Content-Length":len(body)}
            for hdr in res.info():
                headers.update({hdr:res.info()[hdr]})
        except urllib2.HTTPError as e:
            body = e.read()
            headers = {"Status":e.getcode(), "location":e.geturl(), "Content-Length":len(body)}
            for hdr in e.info():
                headers.update({hdr:e.info()[hdr]})
        except urllib2.URLError as e:
            body = ''
            headers = {"Status":595, "location":url, "Content-Length":len(body)}

        def sub(url, ctx, body, headers, port):
            status = int(headers['Status'])
            if debug:
                warn("got status=" + str(status) + " for " + headers['location'])
            if int(status) == 301 or int(status) == 302:
                if debug:
                    warn("http redirect to " + headers['location'] + "\n")
                ctx.update({'url':headers['location']})
                return check(ctx)
            elif int(status) == 401:
                devType = search4devType(body, headers)
                if devType == "":
                    error(ctx['ip'] + ": didnot find dev type after trying all devices")
                    return
                if debug:
                    warn("devType=" + devTpe)
                ctx.update({'devType':devType})
                ctx.update({'url':url})
                ctx.update({'dev':devs[devType]})
                return check_login(ctx, body, port)
            elif int(status) == 200:
                devType = search4devType(body, headers)
                if devType != "":
                    if debug:
                        warn("devType=" + devType)
                    ctx.update({'dev':devs[devType]})
                    ctx.update({'devType':devType})
                    gotoCheckLogin(ctx, url, body, port)
                elif ctx['stage'] == "look4LoginPage":
                    pass
                elif ctx['stage'] == "":
                    try:
                        url = getRefreshUrl(ctx['url'])
                    except:
                        url = ''
                    if url != "":
                        ctx.update({"url":url})
                        ctx.update({"stage":"look4LoginPage"})
                        return check(ctx, port)
            elif int(status) == 404:
                error("canot find dev type for " + ctx['ip'] + " due to 404 response")
                return
            else:
                if int(status) == 595:
                    error("device " + ctx['ip'] + ": failed to establish TCP connection")
                else:
                    error("unexpected status code " + str(status) + " for ip " + ctx['ip'])
                return
            devType = search4devType(body, headers)
            if devType == "":
                error(ctx['ip'] + ": didnot find dev type after trying all devices")
                return
            
            ctx.update({'dev':devs[devType]})
            ctx.update({'devType':devType})
            if int(status) == 401:
                ctx.update({'url':url})
                return check_login(ctx, body, port)
        sub(url, ctx, body, headers, port)
    http_get(url, ctx, port)
    
def composeURL(indict, port):
    ctx = indict
    http_Port = port
    portStr = ":" + str(httpPort) if http_Port != 80 else ""
    try:
        ctx['url']
    except KeyError:
        return "http://" + str(ctx['ip']) + str(portStr) + "/"
    if re.match(r'^https?:', ctx['url']):
        return ctx['url']
    elif re.match(r'^\/', ctx['url']):
        return "http://"+ ctx['ip'] + str(portStr) + ctx['url']
    elif re.match(r'^\/', ctx['url']):
        error("unexpected partial url " +  ctx['url'] + "\n")
        return

def extra_requirements_dict():
    return {}       

def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, language,
          verbose_level, show_version , socks_proxy, retries, ping_flag, scan_id,
          scan_cmd):  # Main function
    readDevices()
    global debug
    global scanid
    global scancmd
    global lang
    global loginfile
    scanid = scan_id
    scancmd = scan_cmd
    lang = language
    loginfile = log_in_file
    debug = verbose_level
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        threads = []
        if ports is not None:
            for port in ports:
                t = threading.Thread(target=check, args=({'ip':target, 'stage':''}, port,))
                threads.append(t)
                t.start()
            
        else:
            check({'ip':target, 'stage':''}, httpPort)
        for t in threads:
            t.join()
