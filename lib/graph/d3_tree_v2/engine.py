#!/usr/bin/env python
# -*- coding: utf-8 -*-
import string
import random
import json


def start(graph_flag, language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION):
    """
    generate the d3_tree_v2_graph with events (using d3_tree_v1_graph)

    Args:
        graph_flag: graph name
        language: language
        data: events in JSON
        _HOST: host key
        _USERNAME: username key
        _PASSWORD: password key
        _PORT: port key
        _TYPE: module name key
        _DESCRIPTION: description key

    Returns:
        a graph in HTML
    """
    from lib.graph.d3_tree_v1.engine import start
    return start(graph_flag, language, data, _HOST, _USERNAME,
                 _PASSWORD, _PORT, _TYPE, _DESCRIPTION).replace('''\t root.children.forEach(function(child){
     collapse(child);
\t });''', '')
