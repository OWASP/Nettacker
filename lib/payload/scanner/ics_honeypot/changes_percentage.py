#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys
import json

HONEYPOT_CHANGES_PERCENTAGE = 11


def files_check():
    try:
        file1 = open(sys.argv[1], "rb").read()
    except Exception as _:
        sys.exit(print("cannot open the file, {0}".format(sys.argv[1])))
    try:
        file2 = open(sys.argv[2], "rb").read()
    except Exception as _:
        sys.exit(print("cannot open the file, {0}".format(sys.argv[2])))
    return [json.loads(file1), json.loads(file2)]


def percentage(data1, data2):
    m = 0
    n = 0
    for r in data1.rsplit():
        try:
            if r == data2.rsplit()[m]:
                n += 1
        except:
            n += 1
        m += 1
    return float(100 / float(float(len(data1.rsplit())) / int(len(data1.rsplit()) - n)))


if __name__ == "__main__":
    if len(sys.argv) is not 3:
        sys.exit(print("usage: python {0} file1.json file2.json".format(sys.argv[0])))
    file1, file2 = files_check()
    for target_selected in file1:
        NOT_FIND_FLAG = True
        for target_find in file2:
            if target_selected["host"] == target_find["host"]:
                PERCENTAGE = percentage(target_selected["I20100_RESPONSE"], target_find["I20100_RESPONSE"])
                print("HOST:{0}\tCHANGE PERCENTAGE:{1}%\tDEFAULT CONFIG:{2}\tI30100 TRAP:{3}".format(
                    target_selected["host"], PERCENTAGE, target_selected["DEFAULT_SIGNATURES"] or
                                                         target_selected["DEFAULT_PRODUCTS"],
                    target_selected["\x01I30100\n"]))
