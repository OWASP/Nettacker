#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from config import nettacker_paths

css_1 = open(
    os.path.join(
        nettacker_paths()['web_static_files_path'],
        'report/html_table.css'
    )
).read()

table_title = open(
    os.path.join(
        nettacker_paths()['web_static_files_path'],
        'report/table_title.html'
    )
).read()

table_items = open(
    os.path.join(
        nettacker_paths()['web_static_files_path'],
        'report/table_items.html'
    )
).read()

table_end = open(
    os.path.join(
        nettacker_paths()['web_static_files_path'],
        'report/table_end.html'
    )
).read()
