#!/usr/bin/env python

import sys
from core import color


def info(content):
    if '-L' in sys.argv or '--logs' in sys.argv:
        f=open('logs.txt','a')
        f.write('[+] ' + str(content) + '\n')
        f.close()
    if '\n' in content:
        num_newline = len(content) - len(content.rstrip("\n"))
        sys.stdout.write(color.color('yellow') + '[+] ' + color.color('green') +
                         content[:-num_newline] + color.color('reset') + "\n"*num_newline)
    else:
        sys.stdout.write(color.color('yellow') + '[+] ' + color.color('green') +
                         content + color.color('reset') + "\n")
    return


def write(content):
    if '-L' in sys.argv or '--logs' in sys.argv:
        f=open('logs.txt','a')
        f.write(str(content) + '\n')
        f.close()
    sys.stdout.write(content)
    return


def warn(content):
    if '-L' in sys.argv or '--logs' in sys.argv:
        f=open('logs.txt','a')
        f.write('[!] ' + str(content) + '\n')
        f.close()
    if '\n' in content:
        num_newline = len(content) - len(content.rstrip("\n"))
        sys.stdout.write(color.color('blue') + '[!] ' + color.color('yellow') +
                        content[:-num_newline] + color.color('reset') + "\n"*num_newline)
    else:
        sys.stdout.write(color.color('blue') + '[!] ' + color.color('yellow') +
                         content + color.color('reset') + "\n")
    return


def error(content):
    if '-L' in sys.argv or '--logs' in sys.argv:
        f=open('logs.txt','a')
        f.write('[X] ' + str(content) + '\n')
        f.close()
    if '\n' in content:
        num_newline = len(content) - len(content.rstrip("\n"))
        sys.stdout.write(color.color('red') + '[X] ' + color.color('yellow') +
                        content[:-num_newline] + color.color('reset') + "\n"*num_newline)
    else:
        sys.stdout.write(color.color('red') + '[X] ' + color.color('yellow') +
                         content + color.color('reset') + "\n")
    return
