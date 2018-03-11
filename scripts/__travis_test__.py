#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

# Test help menu command
os.system("time python nettacker.py --help")
os.system("time python nettacker.py --help -L fa")
# Test show version command
os.system("time python nettacker.py --version")
# Test all modules command + check if it's finish successfully + without graph
if os.system("time python nettacker.py -i 127.0.0.1 -u user1,user2 -p "
             "pass1,pass2 -m all -g 21,25,80,443 -t 10000000 -T 0.1 -v 5 --method-args \"subdomain_scan_time_limit_"
             "seconds=5\"") is not 0:
    sys.exit(1)
# Test all modules command + check if it's finish successfully + with graph
if os.system("time python nettacker.py -i 127.0.0.1 -u user1,user2 -p "
             "pass1,pass2 -m all -g 21,25,80,443 -t 10000000 -T 0.1 --graph d3_tree_v2_graph"
             " --method-args \"subdomain_scan_time_limit_seconds=5\" -v 5 ") is not 0:
    sys.exit(1)
# Test all modules command + check if it's finish successfully + without
# graph + Farsi
if os.system("time python nettacker.py -i 127.0.0.1 -u user1,user2 -p "
             "pass1,pass2 -m all -g 21,25,80,443 -t 10000000 -T 0.1 -L fa "
             "-v 5 --method-args \"subdomain_scan_time_limit_seconds=5\"") is not 0:
    sys.exit(1)
# Test all modules command + check if it's finish successfully + with
# graph + Farsi
if os.system("time python nettacker.py -i 127.0.0.1 -u user1,user2 -p "
             "pass1,pass2 -m all -g 21,25,80,443 -t 10000000 -T 0.1 -L fa --graph d3_tree_v2_graph"
             " -v 5 --method-args \"subdomain_scan_time_limit_seconds=5\"") is not 0:
    sys.exit(1)
# Test all modules for second time (testing cache) command
os.system("time python nettacker.py -i 127.0.0.1 -u user1,user2 -p pass1,pass2 -m all -g 21,25,80,443 -t 10000000"
          " -T 0.1 -v 5 --method-args \"subdomain_scan_time_limit_seconds=5\"")
