**Contents**:

* [Before Installation](#before-installation)
* [Installation methods](#installation)
* [After Installation](#after-installation)


### Supported Platforms

OWASP Nettacker runs on Linux operating system (we recommend using the docker image to be able to run it on any OS). If you would like to run this on your machine you must install all dependencies and at least Python 3.10

PLEASE NOTE: Starting from Nettacker version 0.3.1 the support for Python2 and Python <3.10 has been dropped. If you have a requirement to use Nettacker on Python 2.x or 3.0-3.9 you can use the legacy version of Nettacker [v0.0.2](https://github.com/OWASP/Nettacker/releases/tag/0.0.2) 

### Dependencies

OWASP Nettacker has dependencies on the following libraries and tools:

* libcurl4-openssl-dev
* libcurl4-gnutls-dev
* librtmp-dev
* libssl-dev
* python3-dev
* libpq-dev (required if you wish to use PostgreSQL database)
* libffi-dev 
* musl-dev 
* make
* gcc 
* git

Before using this software, please install the requirements following the commands below:


Install Python 3 first:
```
apt-get update
apt-get install -y python3 python3-dev python3-pip
pip3 install --upgrade pip3
```

Starting from version 0.4.0 Nettacker is now using Poetry Package Manager and can be installed directly from PyPI.

```
python3 -m venv venv
. venv/bin/activate
pip3 install nettacker
nettacker --help
```

PLEASE NOTE: Python version 3.10 or higher is required to run Nettacker.  You can check the version of Python3 installed by running:

```
python3 -V
```

If you have Python 3.10 or higher you should be able to run OWASP Nettacker via command:

`python3 nettacker.py`

or simply

`nettacker`

### Make your life easier using docker
To run the API server, just run `docker-compose up`. if you need to run via command line use the commands below.

```
docker-compose up -d && docker exec -it nettacker_nettacker_1 /bin/bash
```
