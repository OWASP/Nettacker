#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

os.system('python nettacker.py --help')
os.system("python nettacker.py -i 127.0.0.1 -u user1,user2 -p pass1,pass2 -m all -g 21,25,80,443 -t 2 -T 0.1")
