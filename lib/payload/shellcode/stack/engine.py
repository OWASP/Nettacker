#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
from core.alert import error
from core.compatible import version


def shellcoder(shellcode):
    n = 0
    xshellcode = '\\x'
    for w in shellcode:
        n += 1
        xshellcode += str(w)
        if n is 2:
            n = 0
            xshellcode += str('\\x')
    return xshellcode[:-2]


def st(data):
    if version() is 2:
        return str(binascii.b2a_hex(data[::-1]))
    if version() is 3:
        return (binascii.b2a_hex(data[::-1].encode('latin-1'))).decode('latin-1')


def generate(data, register, gtype):
    length = len(data)
    if gtype == 'int':
        flag_8 = True
        try:
            data = hex(int(data, 8))
        except:
            flag_8 = False
        if flag_8 is False:
            try:
                data = hex(int(data, 16))
            except:
                error('hex or digit required!\nExit\n')
    if gtype == 'string':
        data = st(data)
    if length <= 3:
        if gtype == 'string':
            data = str('0x') + str(data)
        if len(data) % 2 is not 0:
            data = data.replace('0x', '0x0')
        if len(data) is 8:
            data = data + '90\npop %s\nshr $0x8,%s\npush %s\n' % (
                register, register, register)
        if len(data) is 6:
            data = data + '9090\npop %s\nshr $0x10,%s\npush %s\n' % (
                register, register, register)
        if len(data) is 4:
            data = data + '909090\npop %s\nshr $0x10,%s\nshr $0x8,%s\npush %s\n' % (
                register, register, register, register)
        data = str('push $') + str(data)
    if length >= 4:
        if gtype == 'int':
            data = data[2:]
        stack_content = data
        shr_counter = len(stack_content) % 8
        shr = None
        if shr_counter is 2:
            shr = '\npop %s\nshr    $0x10,%s\nshr    $0x8,%s\npush %s\n' % (
                register, register, register, register)
            stack_content = stack_content[0:2] + '909090' + stack_content[2:]
        if shr_counter is 4:
            shr = '\npop %s\nshr    $0x10,%s\npush %s\n' % (register, register,
                                                            register)
            stack_content = stack_content[0:4] + '9090' + stack_content[4:]
        if shr_counter is 6:
            shr = '\npop %s\nshr    $0x8,%s\npush %s\n' % (register, register,
                                                           register)
            stack_content = stack_content[0:6] + '90' + stack_content[6:]
        zshr = shr
        m = int(len(stack_content))
        n = int(len(stack_content) / 8)
        file_shellcode = ''
        if (len(stack_content) % 8) is 0:
            shr_n = 0
            r = ''
            while (n is not 0):
                if shr is not None:
                    shr_n += 1
                    zx = m - 8
                    file_shellcode = 'push $0x' + str(stack_content[
                                                      zx:m]) + '\n' + file_shellcode
                    m -= 8
                    n = n - 1
                    shr = None
                if shr is None:
                    shr_n += 1
                    zx = m - 8
                    file_shellcode = 'push $0x' + str(stack_content[
                                                      zx:m]) + '\n' + file_shellcode
                    m -= 8
                    n = n - 1
            if zshr is None:
                file_z = file_shellcode
            if zshr is not None:
                rep1 = file_shellcode[:16]
                rep2 = rep1 + zshr
                file_z = file_shellcode.replace(rep1, rep2)
        data = file_z
    return data
