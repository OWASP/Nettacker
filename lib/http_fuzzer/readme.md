### OWASP Nettacker HTTP Fuzzer
The http fuzzer library of nettacker is stored here.

`__init__.py` is the module initialization file \
`engine.py` contains all the fuzzing functions

The `__repeater()` function in http_fuzzer library taken in the following inputs:
- `request_template`: the sample template of the request(to be supplied by the module)
- `parameters`: the payload in form of [[1,2,3], [1,2,3],...]
- `condition`: the condition to be evaluated. eg: response.status_code == 200
- `sample_event`: the template for the event that will be logged into the db
- `message`: the message that you want to display in the terminal when success
- `counter_message`: the message that you want to display if nothing is found
- `target`: the target to be attacked
- `ports`: the ports to be fuzzed
- `default_ports`: if user doesn't supply ports, these are to be fuzzed
- other args: `retries`, `time_sleep`, `timeout_sec`, `thread_number`, `log_in_file`, `time_sleep`, `language`,
                    `verbose_level`, `socks_proxy`, `scan_id`, `scan_cmd`, `thread_tmp_filename`
                    
#### Calling the `__repeater()` function:
For fuzzing, you need to call the `__repeater()` function. This will take the inputs as given above
and will evaluate the given condition. These are the variables that will be used to get outputs.\
 `response`: This variable holds the response of the requests library after the request is made
 `payload`: This variable holds the corresponding payload to which the result was true. This is an 
 array with the parameters in the order which you give to the function
\
Here is an example of pma_scan:
```
    default_ports = [80, 443]
    request = """{0} __target_locat_here__{{0}} HTTP/1.1
    User-Agent: {1}
    """.format(extra_requirements["pma_scan_http_method"][0], user_agent)
    parameters = list()
    parameters.append(extra_requirements["pma_scan_list"])
    status_codes = [200, 401, 403]
    condition = "response.status_code in {0}".format(status_codes)
    message = messages(language, 'found')
    sample_message = "\"" + message + "\""+""".format(response.url, response.status_code, response.reason)"""
    sample_event = {
        'HOST': target_to_host(target),
        'USERNAME': '',
        'PASSWORD': '',
        'PORT': port,
        'TYPE': 'pma_scan',
        'DESCRIPTION': sample_message,
        'TIME': now(),
        'CATEGORY': "scan",
        'SCAN_ID': scan_id,
        'SCAN_CMD': scan_cmd
    }
    counter_message = messages(language, "phpmyadmin_dir_404")
    __repeater(request, parameters, timeout_sec, thread_number, log_in_file, time_sleep, language,
                            verbose_level, socks_proxy, retries, scan_id, scan_cmd, condition, thread_tmp_filename,
                            sample_event, sample_message, target, ports, default_ports, counter_message)
```
In the sample request, you must specify the target as `__target_locat_here__` as shown in the above example. You will
need to form sample message and sample request in such a way that they can be executed in the framework. More details can be 
found in the Developers wiki section.