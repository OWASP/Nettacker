import copy
import smbprotocol
from core.utility import process_conditions
from core.utility import get_dependent_results_from_database
from core.utility import replace_dependent_values

class NettackSMB:
    def smb_brute_force(self, host, ports, usernames, passwords, timeout):
        smb_client = smbprotocol.SMBClient(host, int(ports))
        try:
            smb_client.login(usernames, passwords, timeout=int(timeout))
            smb_client.logout()
            return {
                "host": host,
                "username": usernames,
                "password": passwords,
                "port": ports
            }
        except smbprotocol.exceptions.AuthenticationError as _:
            pass
        return {}

class Engine:
    def run(
            sub_step,
            module_name,
            target,
            scan_unique_id,
            options,
            process_number,
            module_thread_number,
            total_module_thread_number,
            request_number_counter,
            total_number_of_requests
    ):
        backup_method = copy.deepcopy(sub_step['method'])
        backup_response = copy.deepcopy(sub_step['response'])
        del sub_step['method']
        del sub_step['response']
        if 'dependent_on_temp_event' in backup_response:
            temp_event = get_dependent_results_from_database(
                target,
                module_name,
                scan_unique_id,
                backup_response['dependent_on_temp_event']
            )
            sub_step = replace_dependent_values(
                sub_step,
                temp_event
            )
        action = NettackSMB()
        response = action.smb_brute_force(**sub_step)
        sub_step['method'] = backup_method
        sub_step['response'] = backup_response
        sub_step['response']['conditions_results'] = response
        return process_conditions(
            sub_step,
            module_name,
            target,
            scan_unique_id,
            options,
            response,
            process_number,
            module_thread_number,
            total_module_thread_number,
            request_number_counter,
            total_number_of_requests
        )
