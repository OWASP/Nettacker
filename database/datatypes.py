#!/usr/bin/env python
# -*- coding: utf-8 -*-

from config import nettacker_global_config

elastic_search_types = {
    "ScanEvents": {
        'mappings': {
            'properties': {
                'target': {'type': 'keyword'},
                'module_name': {'type': 'keyword'},
                'nettacker_engine_identifier': {'type': 'keyword'},
                'scan_unique_id': {'type': 'keyword'},
                'sha256_checksum': {'type': 'keyword'},
                'event': {'type': 'nested'},
                'date': {
                    'type': 'date',
                    'format': 'yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis'
                },
                'updated': {
                    'type': 'date',
                    'format': 'yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis'
                }
            }
        }
    },
    "TemporaryScanEvents": {
        'mappings': {
            'properties': {
                'target': {'type': 'keyword'},
                'module_name': {'type': 'keyword'},
                'nettacker_engine_identifier': {'type': 'keyword'},
                'scan_unique_id': {'type': 'keyword'},
                'event_name': {'type': 'keyword'},
                'event': {'type': 'nested'},
                'date': {
                    'type': 'date',
                    'format': 'yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis'
                }
            }
        }
    },
    "Scans": {
        'mappings': {
            'properties': {
                'scan_unique_id': {'type': 'keyword'},
                'options': {'type': 'nested'},
                'status': {'type': 'keyword'},
                'report_path_filename': {'type': 'text'},
                'file_content': {'type': 'binary'},
                'date': {
                    'type': 'date',
                    'format': 'yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis'
                },
                'finished_date': {
                    'type': 'date',
                    'format': 'yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis'
                }
            }
        }
    }
}

redis_types = {
    # can add elasticsearch/health
    'nettacker_engines': {
        nettacker_global_config()['nettacker_engine_identifier']: {
            'scans': {
                'scan_unique_id_holder': {
                    'process_number_holder': {
                        'target_name_holder': {
                            'module_name_holder': {
                                'current_step_holder': 0,
                                'total_steps_holder': 0
                            }
                        }
                    }
                }
            },
            'resource_monitor': {
                'cpu_usage': {
                    'core_number_holder': 0
                },
                'ram_usage': {
                    'in_use': 0,
                    'free': 0,
                    'total_available': 0
                },
                'network_usage': {
                    'bandwidth': {
                        'in': 0,
                        'out': 0
                    },
                    'total_connections': 0
                }
            }
        }
    }
}
