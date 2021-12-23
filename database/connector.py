#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import elasticsearch
from config import nettacker_database_config
from rejson import Client


class RedisConnector:
    def __init__(self):
        self.redis_client = Client(
            host=nettacker_database_config()["redis"]["url"],
            port=nettacker_database_config()["redis"]["port"],
            password=nettacker_database_config()["redis"]["password"],
            decode_responses=True
        )


class ElasticSearchConnector:
    def __init__(self):
        self.elasticsearch_connector = elasticsearch.Elasticsearch(
            nettacker_database_config()["elasticsearch"]["url"],
            http_auth=nettacker_database_config()["elasticsearch"]["http_auth"]
        )
