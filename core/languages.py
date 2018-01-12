#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import xmljson
from xml.etree.ElementTree import fromstring


def all_messages(language):
    messages_default = xmljson.badgerfish.data(
        fromstring(
            open(os.path.dirname(os.path.abspath(__file__)).replace('\\', '/') + '/../lib/language/messages_en.xml',
                 'rb').read()))
    if language == "en":
        return messages_default
    else:
        try:
            message_language = xmljson.badgerfish.data(
                fromstring(open(os.path.dirname(os.path.abspath(__file__))
                                .replace('\\', '/') + '/../lib/language/messages_{0}.xml'.format(
                    language), 'rb').read()))
        except:
            return messages_default
        for msg in message_language["data"]:
            try:
                if message_language["data"][msg]["$"] == "":
                    message_language["data"][msg]["$"] = messages_default["data"][msg]["$"]
            except:
                try:
                    try:
                        message_language["data"][msg]["$"] = messages_default["data"][msg]["$"]
                    except:
                        message_language["data"][msg]["$"] = ""
                except:
                    pass
        return message_language
