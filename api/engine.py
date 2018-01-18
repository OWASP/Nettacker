#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask
from core.config_builder import _builder
from core.config_builder import _api_default_config
from config import _api_config

app = Flask(__name__)


@app.route('/')
def index():
    return "Hello, World!"


if __name__ == '__main__':
    config = _builder(_api_config(), _api_default_config())
    app.run(host=config["host"], port=config["port"], debug=config["debug_mode"])
