#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

# System info
os.system('free -m')
os.system('mpstat -P ALL')
os.system('cat /proc/cpuinfo')
# Test help menu command
os.system('time python nettacker.py --help')
# Test show version command
os.system('time python nettacker.py --version')
# Test all modules command + check if it's finish successfully + without graph
if os.system("time python nettacker.py -i 127.0.0.1 -u user1,user2 -p "
             "pass1,pass2 -m all -g 21,25,80,443 -t 2 -T 0.1") is not 0:
    sys.exit(1)
# Test all modules command + check if it's finish successfully + with graph
if os.system("time python nettacker.py -i 127.0.0.1 -u user1,user2 -p "
             "pass1,pass2 -m all -g 21,25,80,443 -t 2 -T 0.1 --graph d3_tree_v2_graph") is not 0:
    sys.exit(1)
# Test all modules command + check if it's finish successfully + without graph + Farsi
if os.system("time python nettacker.py -i 127.0.0.1 -u user1,user2 -p "
             "pass1,pass2 -m all -g 21,25,80,443 -t 2 -T 0.1 -L fa") is not 0:
    sys.exit(1)
# Test all modules command + check if it's finish successfully + with graph + Farsi
if os.system("time python nettacker.py -i 127.0.0.1 -u user1,user2 -p "
             "pass1,pass2 -m all -g 21,25,80,443 -t 2 -T 0.1 -L fa --graph d3_tree_v2_graph") is not 0:
    sys.exit(1)
# Test all modules for second time (testing cache) command
os.system("time python nettacker.py -i 127.0.0.1 -u user1,user2 -p pass1,pass2 -m all -g 21,25,80,443 -t 2 -T 0.1")
