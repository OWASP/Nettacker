#!/usr/bin/env python
# -*- coding: utf-8 -*-
import string
import random
import json


def start(graph_flag, language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION):
    from lib.graph.d3_tree_v1.engine import start
    return start(graph_flag, language, data, _HOST, _USERNAME,
                 _PASSWORD, _PORT, _TYPE, _DESCRIPTION).replace('''\t root.children.forEach(function(child){
     collapse(child);
\t });''', '')
