#!/usr/bin/env python
# -*- coding: utf-8 -*-

from config import nettacker_global_config

redis_types = {
    # Scan event
    "nettacker_events": {
        "target_holder": {
            "module_name_holder": [
                {
                    "nettacker_engine_identifier": nettacker_global_config()['nettacker_engine_identifier'],
                    "scan_unique_id": "scan_unique_id_holder",
                    "sha256_checksum": "",
                    "human_readable_event": "",
                    "event": {},
                    # "options": {},
                    "date": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
                    # "updated": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                }
            ]
        }
    },
    "nettacker_temporary_events": {
        "target_holder": {
            "module_name_holder": [
                {
                    "nettacker_engine_identifier": nettacker_global_config()['nettacker_engine_identifier'],
                    "scan_unique_id": "scan_unique_id_holder",
                    "sha256_checksum": "",
                    "event_name": "",
                    "event": {},
                    # "options": {},
                    "date": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
                    # "updated": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                }
            ]
        }
    },
    "nettacker_scans": {
        "scan_unique_id_holder": {
            "options": {},
            "events": {
                "target_holder": {
                    "module_name_holder": {
                        "nettacker_engine_identifier": nettacker_global_config()['nettacker_engine_identifier'],
                        "scan_unique_id": "scan_unique_id_holder",
                        "sha256_checksum": "",
                        "event": {},
                        "date": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
                        "updated": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"

                    }
                }
            },
            "status": "",
            "report_path_filename": "",
            "file_content": "",
            "date": "",
            "finished_date": ""
        }
    },
    # engines and threads
    'nettacker_engines': {
        nettacker_global_config()['nettacker_engine_identifier']: {
            'scans': {
                'scan_unique_id_holder': {
                    'options': 'options_holder',
                    'expanded_targets': {},
                    'processes': {
                        'process_name_holder': {
                            'target_name_holder': {
                                'module_name_holder': {
                                    'current_step_holder': 0,
                                    'total_steps_holder': 0
                                }
                            }
                        }
                    }
                }
            },
            # 'resource_monitor': {
            #     'cpu_usage': {
            #         'core_number_holder': 0
            #     },
            #     'ram_usage': {
            #         'in_use': 0,
            #         'free': 0,
            #         'total_available': 0
            #     },
            #     'network_usage': {
            #         'bandwidth': {
            #             'in': 0,
            #             'out': 0
            #         },
            #         'total_connections': 0
            #     }
            # }
        }
    }
}
