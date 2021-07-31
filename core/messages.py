#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import yaml
from io import StringIO


def load_yaml(filename):
    return yaml.load(
        StringIO(
            open(filename, 'r').read()
        ),
        Loader=yaml.FullLoader
    )


class load_message:
    def __init__(self):
        from core.utility import application_language
        from config import nettacker_global_config
        self.language = application_language()
        self.messages = load_yaml(
            "{messages_path}/{language}.yaml".format(
                messages_path=nettacker_global_config()['nettacker_paths']['messages_path'],
                language=self.language
            )
        )
        if self.language != 'en':
            self.messages_en = load_yaml(
                "{messages_path}/en.yaml".format(
                    messages_path=nettacker_global_config()['nettacker_paths']['messages_path']
                )
            )
            for message_id in self.messages_en:
                if message_id not in self.messages:
                    self.messages[message_id] = self.messages_en[message_id]
