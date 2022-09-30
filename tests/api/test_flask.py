#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import random
import string
import asyncio
from config import nettacker_api_config
from core.module_protocols.core_http import send_request

api_configurations = nettacker_api_config()
api_configurations["api_access_key"] = "test"
api_configurations['api_url'] = "https://{hostname}:{port}".format(
    hostname=api_configurations['api_hostname'],
    port=api_configurations['api_port']
)


class TestAPIEndpoints(unittest.TestCase):
    def test_api_endpoint_index(self):
        """
        test api endpoint index
        """
        # GET /
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'],
                    "ssl": False
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)

        # GET / with api_key in cookies
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'],
                    "ssl": False,
                    "cookies": {
                        "api_key": api_configurations["api_access_key"]
                    }
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)

        # GET / with api_key in cookies + random string
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'],
                    "ssl": False,
                    "cookies": {
                        "api_key": api_configurations["api_access_key"] + random.choice(string.ascii_lowercase)
                    }
                },
                method="get"
            )
        )
        # GET / does not need authentication so status should be 200
        self.assertEqual(int(response["status_code"]), 200)

    def test_api_endpoint_cookie_set_get(self):
        """
        test api endpoint cookie set
        """
        # GET /cookie/set without api_key
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/set",
                    "ssl": False
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 401)

        # GET /cookie/set?api_key={api_key}
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/set?api_key={api_key}".format(
                        api_key=api_configurations['api_access_key']
                    ),
                    "ssl": False
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)
        self.assertEqual(
            response["headers"]['Set-Cookie'],
            "api_key={api_key}; Path=/".format(api_key=api_configurations['api_access_key'])
        )

        # GET /cookie/set?api_key={api_key} + random string
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/set?api_key={api_key}".format(
                        api_key=api_configurations['api_access_key'] + random.choice(string.ascii_letters)
                    ),
                    "ssl": False
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 401)

        # GET /cookie/set with api_key in cookies
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/set",
                    "ssl": False,
                    "cookies": {
                        "api_key": api_configurations["api_access_key"]
                    }
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)
        self.assertEqual(
            response["headers"]['Set-Cookie'],
            "api_key={api_key}; Path=/".format(api_key=api_configurations['api_access_key'])
        )

        # GET /cookie/set with api_key in cookies + random string
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/set",
                    "ssl": False,
                    "cookies": {
                        "api_key": api_configurations["api_access_key"] + random.choice(string.ascii_letters)
                    }
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 401)

    def test_api_endpoint_cookie_set_post(self):
        # POST /cookie/set without api_key
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/set",
                    "ssl": False
                },
                method="post"
            )
        )
        self.assertEqual(int(response["status_code"]), 401)

        # POST /cookie/set with api_key in data
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/set",
                    "ssl": False,
                    "data": {
                        "api_key": api_configurations['api_access_key']
                    }
                },
                method="post"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)
        self.assertEqual(
            response["headers"]['Set-Cookie'],
            "api_key={api_key}; Path=/".format(api_key=api_configurations['api_access_key'])
        )

        # POST /cookie/set with api_key in data + random string
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/set",
                    "ssl": False,
                    "data": {
                        "api_key": api_configurations['api_access_key'] + random.choice(string.ascii_letters)
                    }
                },
                method="post"
            )
        )
        self.assertEqual(int(response["status_code"]), 401)

        # POST /cookie/set with api_key in cookies
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/set",
                    "ssl": False,
                    "cookies": {
                        "api_key": api_configurations["api_access_key"]
                    }
                },
                method="post"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)
        self.assertEqual(
            response["headers"]['Set-Cookie'],
            "api_key={api_key}; Path=/".format(api_key=api_configurations['api_access_key'])
        )

        # POST /cookie/set with api_key in cookies + random string
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/set",
                    "ssl": False,
                    "cookies": {
                        "api_key": api_configurations["api_access_key"] + random.choice(string.ascii_letters)
                    }
                },
                method="post"
            )
        )
        self.assertEqual(int(response["status_code"]), 401)

    def test_api_endpoint_cookies_delete(self):
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie",
                    "ssl": False,
                },
                method="delete"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)
        self.assertEqual(response["headers"]['Set-Cookie'], "api_key=; Path=/")

    def test_api_endpoint_cookies_check(self):
        # GET /cookie/check without api_key
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/check",
                    "ssl": False,
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 401)

        # GET /cookie/check with api_key in cookies
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/check",
                    "ssl": False,
                    "cookies": {
                        "api_key": api_configurations["api_access_key"]
                    }
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)

        # GET /cookie/check with api_key in cookies + random string
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/cookie/check",
                    "ssl": False,
                    "cookies": {
                        "api_key": api_configurations["api_access_key"] + random.choice(string.ascii_letters)
                    }
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 401)

    def test_api_endpoint_apidocs(self):
        # GET /apidocs without api_key
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/apidocs",
                    "ssl": False
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 401)

        # GET /apidocs with api_key in cookies
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/apidocs",
                    "ssl": False,
                    "cookies": {
                        "api_key": api_configurations["api_access_key"]
                    }
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)

        # GET /apidocs with api_key in cookies + random string
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/apidocs",
                    "ssl": False,
                    "cookies": {
                        "api_key": api_configurations["api_access_key"] + random.choice(string.ascii_letters)
                    }
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 401)

        # GET /apidocs with api_key
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/apidocs?api_key={api_key}".format(
                        api_key=api_configurations['api_access_key']
                    ),
                    "ssl": False
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)

        # GET /apidocs with api_key + random string
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/apidocs?api_key={api_key}".format(
                        api_key=api_configurations['api_access_key'] + random.choice(string.ascii_letters)
                    ),
                    "ssl": False
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 401)

    def test_api_endpoint_with_static_path(self):
        # GET /js/main.js without api_key
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/js/main.js",
                    "ssl": False
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)
        self.assertEqual(response["headers"]['Content-Type'], "application/javascript; charset=utf-8")

        # GET /js/main.js with api_key in cookies
        response = asyncio.run(
            send_request(
                {
                    "url": api_configurations['api_url'] + "/js/main.js",
                    "ssl": False,
                    "cookies": {
                        "api_key": api_configurations["api_access_key"]
                    }
                },
                method="get"
            )
        )
        self.assertEqual(int(response["status_code"]), 200)
        self.assertEqual(response["headers"]['Content-Type'], "application/javascript; charset=utf-8")



