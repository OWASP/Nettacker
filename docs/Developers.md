We gladly support and appreciate anyone who is interested in contributing to OWASP Nettacker. Overall contributors may focus on developing core framework, modules or payloads, language libraries, and media. After reading this document you should be able to get the basic knowledge to start developing. Please note that we are using PEP8 Python code style and [GitHub Actions](https://github.com/OWASP/Nettacker/actions) for checking all new PRs automatically against supported Python versions. If you use any code/library/module with a license, add the license into external license file.

* [Code of Conduct](https://github.com/OWASP/Nettacker/blob/master/CODE_OF_CONDUCT.md)
* [Issue Template](https://github.com/OWASP/Nettacker/blob/master/.github/ISSUE_TEMPLATE.md)
* [PR Template](https://github.com/OWASP/Nettacker/blob/master/.github/PULL_REQUEST_TEMPLATE.md)
* [License](https://github.com/OWASP/Nettacker/blob/master/LICENSE)
* [External Licenses](https://github.com/OWASP/Nettacker/blob/master/EXTERNAL_LIBRARIES_LICENSES.md)

________

* [Contribution Guidelines](#contribution-guidelines)
* [Roadmap](#roadmap)
* [Creating Media](#creating-media)
* [Contribute to Language Libraries](#contribute-to-language-libraries)
  * [Add a New Language Library](#add-a-new-language-library)
  * [Modify/Update Language Libraries](#modify-update-language-libraries)

# Contribution Guidelines

These are the guidelines you need to keep in mind while contributing:

* Use the automated checks: run `make pre-commit` and `make test`
* Thoroughly test your code locally.
* Be sure to add/update related documentation.

In case of any doubts regarding the guidelines please contact the project leaders.

# Roadmap

Developers always could be aware of the OWASP Nettacker roadmap by checking

* 1- Project Management Page <https://github.com/OWASP/Nettacker/projects>
* 2- Issues Page <https://github.com/OWASP/OWASP-Nettacker/issues>

# Creating Media

We appreciated all kind of media to demonstrate the OWASP Nettacker in any language and environment. It is a great activity to help us grow our framework and get more publicity. Currently, we collected a few media on [Media](https://github.com/OWASP/Nettacker/wiki/Media) page. Feel free to post your Media on [this](https://github.com/OWASP/Nettacker/issues/1) page.

# Contribute to Language Libraries

OWASP Nettacker is using multi-language libraries (default English) to create a better user experience. Currently we are supporting `Greek/el`, `French/fr`, `English/en`, `Dutch/nl`, `Pashto/ps`, `Turkish/tr`, `German/de`, `Korean/ko`, `Italian/it`, `Japanese/ja`, `Persian/fa`, `Armenian/hy`, `Arabic/ar`, `Chinese(Simplified)/zh-cn`, `Vietnamese/vi`, `Russian/ru`, `Hindi/hi`, `Urdu/ur`, `Indonesian/id`, `Spanish/es`, `Hebrew/iw`) languages. If you are an expert in one these languages, It would be a great favor to contribute to one of these. If any language you want to contribute is not listed, feel free to follow the below steps to add it.

## Add a New Language Library

In some cases language library does not exist, you can create a new file and add it to the framework.

* 1- Goto `lib/messages`
* 2- Name your message library e.g. `fa.yaml`
* 3- Copy the default language lib (`en.yaml`) and start your translation.
* 4- **Please notice that you should not change the key-value like `scan_started`, `options` and etc. you just need to modify the Values.**

## Modify/Update Language Libraries

To contribute to the existing libraries, You may go to `lib/messages` select the file you want to contribute and

* 1- Translate English messages to the selected language.
* 2- Compare the language library with **English** library and add new messages to this library and translate them.
* 3- Modify the translated messages to better translations.

# Contribute to Modules

Modules exist in path `/modules/module_category`. Currently, we have three categories (scan, brute, vuln). if you need to add more just create a directory with a name! To start a new module you should understand what kind of protocol you want to use. The list of protocols and module functionalities are in `core/module_protocols`. To understand how they work read the below example.

```yaml
info: # this section is to store information about module
  name: dir_scan
  author: OWASP Nettacker Team
  severity: 3
  description: Directory, Backup finder
  reference: https://www.zaproxy.org/docs/alerts/10095/
  profiles: # module will be added to below profiles and user can use --profile scan to run this and other modules in same profile
    - scan
    - http
    - backup
    - low_severity

payloads: # this section stores the payloads
  - library: http # the time of library, you can use multiple library if needed as an array
    verify: false
    timeout: 3
    cert: ""
    stream: false
    proxies: ""
    steps:
      - method: get # type of request
        headers: # headers
          User-Agent: "{user_agent}" # this will be replaced by default user-agent or user input
        URL: # URL is the input we want to fuzz
          nettacker_fuzzer:
            input_format: "{{schema}}://{target}:{{ports}}/{{urls}}" # format of url
            prefix: ""
            suffix: ""
            interceptors:
            data:
              urls:
                - "administrator"
                - "admin"
                - "old"
                - "_vti_bin"
                - "_private"
                - "cgi-bin"
                - "public_html"
                - "images"
              schema:
                - "http"
                - "https"
              ports:
                - 80
                - 443
        response: # response will check if the payload were success
          condition_type: or # could be and/or
          conditions: # could be in header/content/status_code/reason/timeresponse
            status_code:
              regex: 200|403|401
              reverse: false # if true, it will reverse the regex


```

The `http` protocol uses exactly the same inputs as the python `requests` library. if we want to convert the yaml code to python requests it will be:

```python
In [5]: import requests

In [6]: lib=requests

In [7]: lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:443/url", headers={'User-Agent': 'whatever'})
```

The inputs such as `ports` will be replaced by user input and 80,443 is just a default value to hold in case the user did not enter any ports. you can see all user inputs from `config.py`.

Any value that comes in an array in the YAML files will be treated as a loop and it will regenerate the request until all loops are finished.

```python
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:443/url1", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:443/url2", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:443/url3", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:443/url4", headers={'User-Agent': 'whatever'})
```

or

```python
dynamics: http, https, url1, url2 , url3, url4, port 80, port 443
# https
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:443/url1", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:443/url2", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:443/url3", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:443/url4", headers={'User-Agent': 'whatever'})
# http
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="http://www.owasp.org:80/url1", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="http://www.owasp.org:80/url2", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="http://www.owasp.org:80/url3", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="http://www.owasp.org:80/url4", headers={'User-Agent': 'whatever'})

# https on 80
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:80/url1", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:80/url2", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:80/url3", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="https://www.owasp.org:80/url4", headers={'User-Agent': 'whatever'})

# http on 443
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="http://www.owasp.org:443/url1", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="http://www.owasp.org:443/url2", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="http://www.owasp.org:443/url3", headers={'User-Agent': 'whatever'})
lib.get(verify=False, timeout=3, cert="", stream=False, proxies="", url="http://www.owasp.org:443/url4", headers={'User-Agent': 'whatever'})


```

# Contribute to Code Functionality & API & WebUI

Go nuts!
