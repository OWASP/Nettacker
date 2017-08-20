#!/usr/bin/env python
# -*- coding: utf-8 -*-


def all_messages():
    return \
        {
            "0": {
                "en": "Nettacker engine started ...\n\n"
            },
            "1": {
                "en": "python nettacker.py [options]"
            },
            "2": {
                "en": "Nettacker Help Menu"
            },
            "3": {
                "en": "Please read license and agreements https://github.com/Nettacker/Nettacker"
            },
            "4": {
                "en": "Engine"
            },
            "5": {
                "en": "Engine input options"
            },
            "6": {
                "en": "select a language {0}"
            },
            "7": {
                "en": "scan all IPs in range"
            },
            "8": {
                "en": "find and scan subdomains"
            },
            "9": {
                "en": "thread numbers for connections to a host"
            },
            "10": {
                "en": "thread numbers for scan hosts"
            },
            "11": {
                "en": "save all logs in file (results.txt, results.html)"
            },
            "12": {
                "en": "Target"
            },
            "13": {
                "en": "Target input options"
            },
            "14": {
                "en": "target(s) list, separate with \",\""
            },
            "15": {
                "en": "read target(s) from file"
            },
            "16": {
                "en": "Scan method options"
            },
            "17": {
                "en": "choose scan method {0}"
            },
            "18": {
                "en": "choose scan method to exclude {0}"
            },
            "19": {
                "en": "username(s) list, separate with \",\""
            },
            "20": {
                "en": "read username(s) from file"
            },
            "21": {
                "en": "password(s) list, separate with \",\""
            },
            "22": {
                "en": "read passwords(s) from file"
            },
            "23": {
                "en": "port(s) list, separate with \",\""
            },
            "24": {
                "en": "read passwords(s) from file"
            },
            "25": {
                "en": "time to sleep between each request"
            },
            "26": {
                "en": "Cannot specify the target(s)"
            },
            "27": {
                "en": "Cannot specify the target(s), unable to open file: {0}"
            },
            "28": {
                "en": "it\"s better to use thread number lower than 100, BTW we are continuing..."
            },
            "29": {
                "en": "set timeout to {0} seconds, it is too big, isn\"t it ? by the way we are continuing..."
            },
            "30": {
                "en": "this scan module [{0}] not found!"
            },
            "31": {
                "en": "this scan module [{0}] not found!"
            },
            "32": {
                "en": "you cannot exclude all scan methods"
            },
            "33": {
                "en": "you cannot exclude all scan methods"
            },
            "34": {
                "en": "the {0} module you selected to exclude not found!"
            },
            "35": {
                "en": "please enter one port at least!"
            },
            "36": {
                "en": "this module required username(s) (list) to bruteforce!"
            },
            "37": {
                "en": "Cannot specify the username(s), unable to open file: {0}"
            },
            "38": {
                "en": "this module required password(s) (list) to bruteforce!"
            },
            "39": {
                "en": "Cannot specify the password(s), unable to open file: {0}"
            },
            "40": {
                "en": "file \"{0}\" is not writable!"
            },
            "41": {
                "en": "please choose your scan method!"
            },
            "42": {
                "en": "removing temp files!"
            },
            "43": {
                "en": "sorting results!"
            },
            "44": {
                "en": "done!"
            },
            "45": {
                "en": "start attacking {0}, {1} of {2}"
            },
            "46": {
                "en": "this module \"{0}\" is not available"
            },
            "47": {
                "en": "Sorry, This version of software just could be run on linux/osx/windows."
            },
            "48": {
                "en": "Your python version is not supported!"
            },
            "49": {
                "en": "skip duplicate target (some subdomains/domains may have same IP and Ranges)"
            },
            "50": {
                "en": "unknown type of target [{0}]"
            },
            "51": {
                "en": "checking {0} range ..."
            },
            "52": {
                "en": "checking {0} ..."
            },
            "53": {
                "en": "HOST"
            },
            "54": {
                "en": "USERNAME"
            },
            "55": {
                "en": "PASSWORD"
            },
            "56": {
                "en": "PORT"
            },
            "57": {
                "en": "TYPE"
            },
            "58": {
                "en": "DESCRIPTION"
            },
            "59": {
                "en": "verbose mode level (0-5) (default 0)"
            },
            "60": {
                "en": "show software version"
            },
            "61": {
                "en": "check for update"
            },
            "62": {
                "en": "proxy(s) list, separate with \",\" (out going connections)"
            },
            "63": {
                "en": "read proxies from file (out going connections)"
            },
            "64": {
                "en": "Retries when the connection timeouts (default 3)"
            },
            "65": {
                "en": "ftp connection to {0}:{1} timeout, skipping {2}:{3}"
            },
            "66": {
                "en": "LOGGED IN SUCCESSFULLY!"
            },
            "67": {
                "en": "LOGGED IN SUCCESSFULLY PERMISSION DENIED FOR LIST COMMAND!"
            },
            "68": {
                "en": "ftp connection to {0}:{1} failed, skipping whole step [process {2} of {3}]! going to next step"
            },
            "69": {
                "en": "input target for {0} module must be DOMAIN or SINGLE_IPv4, skipping {1}"
            },
            "70": {
                "en": "user: {0} pass:{1} host:{2} port:{3} found!"
            },
            "71": {
                "en": "(NO PERMISSION FOR LIST FILES)"
            },
            "72": {
                "en": "trying {0} of {1} in process {2} of {3} {4}:{5}"
            },
            "73": {
                "en": "smtp connection to {0}:{1} timeout, skipping {2}:{3}"
            },
            "74": {
                "en": "smtp connection to {0}:{1} failed, skipping whole step [process {2} of {3}]! going to next step"
            },
            "75": {
                "en": "input target for {0} module must be HTTP, skipping {1}"
            },
            "76": {
                "en": "ssh connection to {0}:{1} timeout, skipping {2}:{3}"
            },
            "77": {
                "en": "ssh connection to {0}:{1} failed, skipping whole step [process {2} of {3}]! going to next step"
            },
            "78": {
                "en": "ssh connection to %s:%s failed, skipping whole step [process %s of %s]! going to next step"
            },
            "79": {
                "en": "OPEN PORT"
            },
            "80": {
                "en": "host: {0} port: {1} found!"
            }
        }
