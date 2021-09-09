#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import string
import random
import json


def start(events):
    """
    generate the d3_tree_v2_graph with events (using d3_tree_v1_graph)

    Args:
        events: events

    Returns:
        a graph in HTML
    """
    from lib.graph.d3_tree_v1.engine import start
    return start(events).replace(
        '''\t root.children.forEach(function(child){
     collapse(child);
\t });''',
        ''
    )
