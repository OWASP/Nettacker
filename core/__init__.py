#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from core.compatible import version
from core.compatible import logo
from core.die import die_failure
if version() == 2:
    logo()
    die_failure("Python2 is No longer supported")

logo()
import os
from core.alert import messages
from core.die import die_failure
from config import _core_config
from core.config_builder import _core_default_config
from core.config_builder import _builder

default_config = _builder(_core_config(), _core_default_config())
external_modules = open(default_config["requirements_path"]).read().split('\n')

for module_name in external_modules:
    try:
        __import__(
            module_name.split('==')[0] if 'library_name=' not in module_name
            else module_name.split('library_name=')[1].split()[0]
        )
        #library_name=pip
        #library_name=requests
    except Exception:
        die_failure(
            "pip3 install -r requirements.txt ---> " +
            module_name + " not installed!"
        )

if not os.path.exists(default_config["home_path"]):
    try:
        os.mkdir(default_config["home_path"])
        os.mkdir(default_config["tmp_path"])
        os.mkdir(default_config["results_path"])
    except:
        die_failure("cannot access the directory {0}".format(
            default_config["home_path"]))
if not os.path.exists(default_config["tmp_path"]):
    try:
        os.mkdir(default_config["tmp_path"])
    except:
        die_failure("cannot access the directory {0}".format(
            default_config["results_path"]))
if not os.path.exists(default_config["results_path"]):
    try:
        os.mkdir(default_config["results_path"])
    except:
        die_failure("cannot access the directory {0}".format(
            default_config["results_path"]))
if default_config["database_type"] == "sqlite":
    try:
        if os.path.isfile(
                default_config[
                    "home_path"] + "/" + default_config["database_name"]):
            pass
        else:
            from database.sqlite_create import sqlite_create_tables
            sqlite_create_tables()
    except:
        die_failure("cannot access the directory {0}".format(
            default_config["home_path"]))
elif default_config["database_type"] == "mysql":
    try:
        from database.mysql_create import (
            mysql_create_tables,
            mysql_create_database)
        mysql_create_database()
        mysql_create_tables()
    except:
        die_failure(messages("en", "database_connection_failed"))
elif default_config["database_type"] == "postgres":
    try:
        from database.postgres_create import postgres_create_database
        postgres_create_database()
    except Exception as e:
        die_failure(messages("en", "database_connection_failed"))
else:
    die_failure(messages("en", "invalid_database"))

from core.module_protocols import http
from core.module_protocols import socket
    # default_config = _builder(_core_config(), _core_default_config())
    # external_modules = open(default_config["requirements_path"]).read().split('\n')

        
    # for module_name in external_modules:
    #     try:
    #         __import__(
    #             module_name.split('==')[0] if 'library_name=' not in module_name
    #             else module_name.split('library_name=')[1].split()[0]
    #         )
    #         #library_name=pip
    #         #library_name=requests
    #     except Exception:
    #         die_failure(
    #             "pip3 install -r requirements.txt ---> " +
    #             module_name + " not installed!"
    #         )
