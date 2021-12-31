#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

    @staticmethod
    def normalize_key_name(key_name):
        """
        rejson can't handle dots in keyname, example syntax is .127.0.0.1 -> .["127.0.0.1"]
        Args:
            key_name: json key name

        Returns: normalized key name
        """
        return key_name if '.' not in key_name else "[\"" + key_name + "\"]"

    def write(self, object_name, object_path, object_data, nx=False):
        """
        write json object in redis

        Args:
            object_name: name of dict or object
            object_path: path of dict to update e.g. ".", "a.b.c[0]", "a", "a.b"
            object_data: dict/array as data
            nx: write if not exist

        Returns: coroutine/bool

        """
        return self.redis_client.jsonset(
            object_name,
            object_path,
            object_data,
            nx=nx
        )

    def append(self, object_name, object_path, object_data):
        return self.redis_client.jsonarrappend(
            object_name,
            object_path,
            object_data
        )

    def read(self, object_name, object_path):
        """
        read json object in redis

        Args:
            object_name: name of dict or object
            object_path: path of data

        Returns: dict/array/value
        """
        return self.redis_client.jsonget(
            object_name,
            object_path
        )

    def delete(self, object_name, object_path):
        """
        remove json object in redis

        Args:
            object_name: name of dict or object
            object_path: path of data

        Returns: bool
        """
        return self.redis_client.jsondel(
            object_name,
            object_path
        )


class ElasticSearchConnector:
    def __init__(self):
        self.elasticsearch_connector = elasticsearch.Elasticsearch(
            nettacker_database_config()["elasticsearch"]["url"],
            http_auth=nettacker_database_config()["elasticsearch"]["http_auth"]
        )
