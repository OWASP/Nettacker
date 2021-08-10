#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import string
import random
import json


def start(graph_name, language, data, date, target, module_name, scan_unique_id, options, event):
    """
    generate the d3_tree_v2_graph with events (using d3_tree_v1_graph)

    Args:
        graph_name: graph name
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
    return start(graph_name, language,
                 data, date, target, module_name, scan_unique_id, options, event).replace('''\t root.children.forEach(function(child){
     collapse(child);
\t });''', '')
