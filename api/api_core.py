#!/usr/bin/env python
# -*- coding: utf-8 -*-


def __structure(status="", msg=""):
    return {
        "status": status,
        "msg": msg
    }


def __get_value(flask_request, _key):
    try:
        key = flask_request.args[_key]
    except:
        try:
            key = flask_request.form[_key]
        except:
            key = None
    return key
