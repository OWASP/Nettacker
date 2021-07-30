#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.compatible import check_dependencies
if(check_dependencies()):
    from core.module_protocols import http
    from core.module_protocols import socket