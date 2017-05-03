#!/usr/bin/env python

from core.alert import *

def start_attack(target,num,total,scan_method):
    info(str('start attacking ' + str(target) + ' %s of %s '%(str(num),str(total))))