from core.alert import *
from core.targets import target_type
from core.targets import target_to_host


def requirements_check(**kwargs):
    '''
    Args: 
        target_to_host = default(true), scan_name

    E.g:
        @requirements_check(target_to_host=true,scan_name='xss_vuln')
        def start(*args):
    '''
    # for target to host bool
    try:
        if kwargs['target_to_host']:
            target_to_host_bool = kwargs['target_to_host']
    except KeyError:
        target_to_host_bool = True

    # for scan-name
    try:
        if kwargs['scan_name']:
            scan_name = kwargs['scan_name']
    except KeyError:
        scan_name = 'some module'

    def start_function_taker(func_name):
        '''
        takes start function in general
        '''

        def requirement_checker_with_func_args(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
                                               verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):
            if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
                if target_to_host_bool and target_type(target) == 'HTTP':
                    target = target_to_host(target)

                # importing module which is asking
                extra_requirements_dict = func_name.__globals__[
                    'extra_requirements_dict']
                # requirements check

                new_extra_requirements = extra_requirements_dict()
                if methods_args is not None:
                    for extra_requirement in extra_requirements_dict():
                        if extra_requirement in methods_args:
                            new_extra_requirements[
                                extra_requirement] = methods_args[extra_requirement]
                extra_requirements = new_extra_requirements
                func_name.__globals__[
                    'extra_requirements'] = extra_requirements
                # info(messages(language, "done"))
                return func_name(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
                                 verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd)

            else:
                warn(messages(language, "input_target_error").format(
                    scan_name, target))

        return requirement_checker_with_func_args

    return start_function_taker
