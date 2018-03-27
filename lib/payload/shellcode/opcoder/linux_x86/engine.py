#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
from lib.payload.shellcode.stack import engine as stack
from core.compatible import version

replace_values_static = {
    'xor %ebx,%ebx': '31 db',
    'xor %ecx,%ecx': '31 c9',
    'xor %eax,%ebx': '31 c3',
    'xor %ecx,%ebx': '31 cb',
    'xor %ebx,%eax': '31 d8',
    'xor %eax,%eax': '31 c0',
    'xor %ebx,%edx': '31 da',
    'xor %edx,%edx': '31 d2',
    'mov %esp,%ebx': '89 e3',
    'mov $0x1,%al': 'b0 01',
    'mov $0x01,%al': 'b0 01',
    'mov $0x1,%bl': 'b3 01',
    'mov $0x01,%bl': 'b3 01',
    'mov $0xb,%al': 'b0 0b',
    'mov %eax,%ebx': '89 c3',
    'mov %esp,%ecx': '89 e1',
    'mov %esp,%esi': '89 e6',
    'shr $0x10,%ebx': 'c1 eb 10',
    'shr $0x08,%ebx': 'c1 eb 08',
    'shr $0x8,%ebx': 'c1 eb 08',
    'shr $0x10,%eax': 'c1 e8 10',
    'shr $0x08,%eax': 'c1 e8 08',
    'shr $0x8,%eax': 'c1 e8 08',
    'shr $0x10,%ecx': 'c1 e9 10',
    'shr $0x8,%ecx': 'c1 e9 08',
    'shr $0x08,%ecx': 'c1 e9 08',
    'shr $0x10,%edx': 'c1 ea 10',
    'shr $0x8,%edx': 'c1 ea 08',
    'shr $0x08,%edx': 'c1 ea 08',
    'inc %eax': '40',
    'inc %ebx': '43',
    'inc %ecx': '41',
    'inc %edx': '42',
    'dec %eax': '48',
    'dec %ebx': '4b',
    'dec %ecx': '49',
    'dec %edx': '4a',
    'add %ecx,%ebx': '01 cb',
    'add %eax,%ebx': '01 c3',
    'add %ebx,%edx': '01 da',
    'add %ebx,%eax': '01 d8',
    'push %eax': '50',
    'push %ebx': '53',
    'push %ecx': '51',
    'push %edx': '52',
    'push %esi': '56',
    'push %edi': '57',
    'neg %eax': 'f7 d8',
    'neg %ebx': 'f7 db',
    'neg %ecx': 'f7 d9',
    'neg %edx': 'f7 da',
    'sub %eax,%ebx': '29 c3',
    'sub %ebx,%edx': '29 da',
    'sub %ebx,%eax': '29 d8',
    'sub %ebx,%ecx': '29 d9',
    'sub %ecx,%ebx': '29 cb',
    'pop %eax': '58',
    'pop %ebx': '5b',
    'pop %ecx': '59',
    'pop %edx': '5a',
    'cltd': '99',
    'int $0x80': 'cd 80',
}


def convert(shellcode):
    shellcode = shellcode.replace('\n\n', '\n').replace('\n\n', '\n').replace(
        '    ', ' ').replace('   ', ' ')
    for data in replace_values_static:
        shellcode = shellcode.replace(data, replace_values_static[data])
    new_shellcode = shellcode.rsplit('\n')
    dynamics = ''
    for line in new_shellcode:
        if 'xor' in line:
            if '$0x' in line:
                if '%eax' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) is 8 or len(line.rsplit(',')[
                                                                0]) is 9:
                        rep = str('83 f0') + str(line.rsplit('$0x')[1].rsplit(
                            ',')[0])
                        shellcode = shellcode.replace(line, rep)
                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('35') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('35') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('35') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('35') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)
                if '%ebx' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('81 f3') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('81 f3') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('81 f3') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('81 f3') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)
                if '%ecx' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('81 f1') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('81 f1') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('81 f1') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('81 f1') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)
                if '%edx' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('81 f2') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('81 f2') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('81 f2') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('81 f2') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)

        if 'add' in line:
            if '$0x' in line:
                if '%eax' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) is 8 or len(line.rsplit(',')[
                                                                0]) is 9:
                        rep = str('83 c0') + str(line.rsplit('$0x')[1].rsplit(
                            ',')[0])
                        shellcode = shellcode.replace(line, rep)
                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('05') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('05') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('05') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('05') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)
                if '%ebx' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('81 c3') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('81 c3') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('81 c3') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('81 c3') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)
                if '%ecx' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('81 c1') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('81 c1') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('81 c1') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('81 c1') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)
                if '%edx' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('81 c2') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('81 c2') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('81 c2') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('81 c2') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)

        if 'sub' in line:
            if '$0x' in line:
                if '%eax' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) is 8 or len(line.rsplit(',')[
                                                                0]) is 9:
                        rep = str('83 e8') + str(line.rsplit('$0x')[1].rsplit(
                            ',')[0])
                        shellcode = shellcode.replace(line, rep)

                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('2d') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('2d') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('2d') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('2d') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)
                if '%ebx' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('81 eb') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('81 eb') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('81 eb') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('81 eb') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)
                if '%ecx' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('81 e9') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('81 e9') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('81 e9') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('81 e9') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)
                if '%edx' in line.rsplit(',')[1]:
                    if len(line.rsplit(',')[0]) >= 14:
                        try:
                            if version() is 2:
                                rep = str('81 ea') + str(stack.st(
                                    binascii.a2b_hex(str(line.rsplit('$0x')[
                                                             1].rsplit(',')[0]))))
                            if version() is 3:
                                rep = str('81 ea') + str(stack.st(
                                    (binascii.a2b_hex((line.rsplit('$0x')[
                                        1].rsplit(',')[0]).encode('latin-1'))
                                    ).decode('latin-1')))
                            shellcode = shellcode.replace(line, rep)
                        except:
                            if version() is 2:
                                rep = str('81 ea') + str(stack.st(
                                    binascii.a2b_hex(str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0]))))
                            if version() is 3:
                                rep = str('81 ea') + str(stack.st((
                                    binascii.a2b_hex((str('0') + str(
                                        line.rsplit('$0x')[1].rsplit(',')[
                                            0])).encode('latin-1'))).decode(
                                    'latin-1')))
                        shellcode = shellcode.replace(line, rep)
        if 'mov $0x' in line:
            if len(line) is 13 or len(line) is 12:
                if '%al' in line.rsplit(',')[1]:
                    rep = str('b0') + str(line.rsplit('$0x')[1].rsplit(',')[0])
                    shellcode = shellcode.replace(line, rep)
                if '%bl' in line.rsplit(',')[1]:
                    rep = str('b3') + str(line.rsplit('$0x')[1].rsplit(',')[0])
        if 'push $0x' in line:
            if len(line) is 9:
                rep = str('6a0') + str(line.rsplit('$0x')[1])
                shellcode = shellcode.replace(line, rep, 1)
            if len(line) is 10:
                rep = str('6a') + str(line.rsplit('$0x')[1])
                shellcode = shellcode.replace(line, rep, 1)
            if len(line) is 15:
                if version() is 2:
                    rep = str('68') + stack.st(str(binascii.a2b_hex(str(
                        '0') + str(line.rsplit('$0x')[1]))))
                if version() is 3:
                    rep = str('68') + stack.st((binascii.a2b_hex((str(
                        '0') + str(line.rsplit('$0x')[1])).encode('latin-1'))
                                               ).decode('latin-1'))
                shellcode = shellcode.replace(line, rep)
            if len(line) is 16:
                if version() is 2:
                    rep = str('68') + stack.st(str(binascii.a2b_hex(str(
                        line.rsplit('$0x')[1]))))
                if version() is 3:
                    rep = str('68') + stack.st(((binascii.a2b_hex((line.rsplit(
                        '$0x')[1]).encode('latin-1'))).decode('latin-1')))
                shellcode = shellcode.replace(line, rep)
    shellcode = stack.shellcoder(shellcode.replace('\n', '').replace(' ', ''))
    return shellcode
