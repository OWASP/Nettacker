#!/usr/bin/env python

from core.input_type import load
from core.targets import analysis
def engine(argvs):
    try:
        targets = open(argvs[1]).read().rsplit()
    except:
        print 'no input'
        return []
    targets = load(targets)
    print 'Targets list ...'
    for target in targets:
        print 'Target:',target,'Type:',targets[target]
        analysis(targets)
    return 0