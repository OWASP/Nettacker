#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import sys
import threading
import time
import socket
import xmltodict
import json

# from lib.payload.scanner.service.engine import recv_all

COMMANDS = [
    {
        "\x01I30100\n": ["9999FF1B"]
    },
    {
        "\x01I20100\n": ["I20100", "IN-TANK INVENTORY"]
    }
]

# https://github.com/sjhilt/GasPot/blob/master/config.ini.dist
DEFAULT_SIGNATURES = [
    "EXXON STATION\n    12 Fake St\n    Anytown, MO 12346", "FUEL COOP", "SHELL STATION", "AMOCO FUELS",
    "MOBIL STATION", "MARATHON GAS", "CHEVRON STATION", "CITGO FUELS", "BP FUELS", "PILOT TRUCK STOP",
    "FLYING J TRUCK STOP", "LOVES FUEL STATION", "SINCLAIR FUEL", "VICTORY OIL", "CONOCO FUELS", "76 OIL",
    "TEXACO STATION", "PETRO-CANADA", "TOTAL PETROL", "HEM PETROL", "ARAL PETROL", "OBERT 24h", "AGIP PETROL",
    "ROMPETROL STATION", "PETRON STATION", "CIRCLE K STATION", "LUK OIL", "MURPHY OIL"]

DEFAULT_PRODUCTS = ["SUPER", "UNLEAD", "DIESEL", "PREMIUM"]


def recv_all(s, limit=4196):
    """
    receive all data from a socket

    Args:
        s: python socket
        limit: limit size to get response

    Returns:
        response or b""
    """
    response = ""
    while len(response) < limit:
        try:
            r = s.recv(1)
            if r != b"":
                response += r.decode()
            else:
                break
        except Exception as _:
            break
    return response


def info(msg, response=None, output=None):
    sys.stdout.write("[+] " + msg + "\n")
    if response and output:
        f = open(output, "a")
        f.write(json.dumps(response) + "\n")
        f.close()


def sort_output(output, target_length):
    data = list(set(open(output).read().rsplit("\n")))
    data_json = []
    for res in data:
        if res.startswith("{"):
            data_json.append(json.loads(res))
    info("{0}/{1} possible honeypot founds".format(len(data_json), target_length))
    f = open(output, "w")
    f.write(json.dumps(data_json))
    f.close()


def first_ics_connect(target, port, timeout, output):
    __JSON_STRUCTURE = {"host": target}
    response = ""
    for CMD in COMMANDS:
        for CMD_NAME in CMD:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((target, port))
                s.send(CMD_NAME)
                response = recv_all(s, limit=1000000)
                FLAG = True
                for RES in CMD[CMD_NAME]:
                    if RES not in response:
                        FLAG = False
                __JSON_STRUCTURE[CMD_NAME] = FLAG
            except Exception as _:
                __JSON_STRUCTURE[CMD_NAME] = False
    if __JSON_STRUCTURE["\x01I20100\n"]:
        __JSON_STRUCTURE["I20100_RESPONSE"] = response
        FLAG = False
        for SIG in DEFAULT_SIGNATURES:
            if SIG in response:
                FLAG = True
        __JSON_STRUCTURE["DEFAULT_SIGNATURES"] = FLAG

        FLAG = True
        for PRD in DEFAULT_PRODUCTS:
            if PRD not in response:
                FLAG = False
        __JSON_STRUCTURE["DEFAULT_PRODUCTS"] = FLAG

        info("possible found honeypot {0}".format(target), response=__JSON_STRUCTURE, output=output)
    return


def read_targets(filename):
    try:
        data = open(filename, "rb").read()
    except Exception as _:
        sys.exit(info("cannot open the file[{0}]".format(filename)))
    if filename.endswith(".xml"):
        loaded_data = json.loads(json.dumps(xmltodict.parse(data)))
        hosts = []
        try:
            for tag in loaded_data["nmaprun"]["host"]:
                hosts.append(json.loads(json.dumps(json.loads(json.dumps(tag))["address"]))["@addr"])
        except Exception as _:
            sys.exit(info("some error occurred while parsing targets from {0}".format(filename)))
    elif filename.endswith(".txt"):
        hosts = list(set(data.rsplit()))
    else:
        sys.exit(info("file extension not supported. (only .txt and .xml)"))
    if not len(hosts):
        sys.exit(info("no targets found in this file {0}".format(filename)))
    return hosts


def clear_threads(threads):
    for thread in threads:
        try:
            thread._Thread__stop()
        except:
            pass


def start():
    parser = argparse.ArgumentParser(prog="ICS Hunter", add_help=False)
    engineOpt = parser.add_argument_group("Options")
    engineOpt.add_argument("-h", "--help", action="store_true",
                           default=False, dest="help_menu", help="show this help menu")
    engineOpt.add_argument("-i", "--targets", action="store", dest="target", default=None,
                           help="input targets (e.g. masscan-gaspot.xml, lists.txt)")
    engineOpt.add_argument("-p", "--port", action="store", dest="port", default=10001, type=int,
                           help="port number")
    engineOpt.add_argument("-t", "--threads", action="store", dest="threads", default=500, type=int,
                           help="max threads number")
    engineOpt.add_argument("-T", "--timeout", action="store", dest="timeout", default=3, type=int,
                           help="timeout seconds")
    engineOpt.add_argument("-o", "--output", action="store", dest="output", default="results.json",
                           help="output filename (e.g. results.json)")
    engineOpt.add_argument("-a", "--alert", action="store", dest="alert", default=1000, type=int,
                           help="alert every x thread to show position")

    args = parser.parse_args()
    if len(sys.argv) <= 1 or "-h" in sys.argv or "--help" in sys.argv:
        parser.print_help()
    targets = read_targets(args.target)
    try:
        f = open(args.output, "w")
        f.write("")
        f.close()
    except:
        sys.exit(info("{0} is not writable!".format(args.output)))
    n = 1
    BREAK = False
    threads = []
    for target in targets:
        if n % args.alert is 0:
            info(str(n) + "/" + str(len(targets)) + "->" + target)
        thread = threading.Thread(target=first_ics_connect, args=(target, args.port, args.timeout, args.output)).start()
        threads.append(thread)
        while 1:
            try:
                if not threading.activeCount() - 1 >= args.threads:
                    break
                time.sleep(0.01)
            except KeyboardInterrupt:
                BREAK = True
                break
        if BREAK:
            break
        n += 1
        if int(n % 2000) is 0:
            time.sleep(args.timeout + 1)
            info("clearing cache")
            clear_threads(threads)
            info("cache cleaned")
            threads = []

    time.sleep(args.timeout + 1)
    info("clearning cache")
    clear_threads(threads)
    info("cache cleaned")
    time.sleep(args.timeout + 1)
    sort_output(args.output, len(targets))
    sys.exit(0)


if __name__ == "__main__":
    start()
