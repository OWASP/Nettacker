# Installation

You have multiple options for installing OWASP Nettacker, each with specific instructions provided in dedicated sections below. 


### Supported Platforms

OWASP Nettacker is designed to run on Linux and macOS systems. However, you can leverage the Docker image to run it on other operating systems as well. Although native Windows support was initially dropped, we are currently working towards reintroducing it in future versions, along with FreeBSD support.

PLEASE NOTE: Starting from Nettacker version 0.3.1 the support for Python2 and Python <3.10 has been dropped. If you have a requirement to use Nettacker on Python 2.x or 3.0-3.9 you can use the legacy version of Nettacker [v0.0.2](https://github.com/OWASP/Nettacker/releases/tag/0.0.2) 


PLEASE NOTE: Python version 3.10-3.12 is required to run Nettacker.  You can check the version of Python3 installed by running:

```
python3 -V
```



### Pre-requisites

OWASP Nettacker depends on several libraries and tools which you might need to install if they are not already installed on your system:

* python3-dev
* python3-pip
* libcurl4-openssl-dev
* libcurl4-gnutls-dev
* librtmp-dev
* libssl-dev
* libpq-dev (required if you wish to use PostgreSQL database)
* libffi-dev 
* musl-dev 
* make
* gcc 
* git

Before using this software, please install the prerequisites by following the commands below):


Install Python3, PIP and VENV first (e.g. on Debian Linux/Ubuntu):
```
sudo apt-get update
sudo apt-get install -y python3 python3-dev python3-pip python3-venv
pip3 install --upgrade pip3
```


### Install Nettacker From PyPI Using PIPX

Installing OWASP Nettacker using `pipx` is a convenient method for managing Python applications with isolated environments. `pipx` ensures that each installed tool has its own environment, avoiding dependency conflicts.

Here’s how you can install OWASP Nettacker using `pipx`:

1. Install pipx using apt or pip

   
Using apt:
```
sudo apt update
sudo apt install pipx
pipx ensurepath
pipx --version
```
or install pipx using using pip:

```
python3 -m pip install --user pipx
python3 -m pipx ensurepath
```

2. Install **nettacker** using pipx
```
pipx install nettacker
nettacker --help
```
### Install Nettacker from PyPI using PIP


Starting from version 0.4.0 Nettacker and can be installed directly from PyPI.

```
sudo apt update
sudo apt install python3-venv python3-pip
python3 -m venv venv
. venv/bin/activate
pip3 install nettacker
nettacker --help
```

### Install Nettacker using Git Clone and PIP

```
sudo apt update
sudo apt install python3-venv python3-pip git
python3 -m venv venv
. venv/bin/activate
git clone https://github.com/OWASP/Nettacker --depth 1
cd Nettacker
pip3 install .
python3 nettacker.py --help
```

You can also run Nettacker after installation like this:

```
nettacker --help
```

### Install Nettacker using Git Clone and Poetry

```
sudo apt update
sudo apt install python3-poetry git
git clone https://github.com/OWASP/Nettacker --depth 1
cd Nettacker
poetry install
poetry run nettacker --help
```

### What Happened to requirements.txt in Nettacker?

In recent updates to OWASP Nettacker, the project has transitioned away from using the traditional `requirements.txt` file for dependency management. Starting from version 0.4.0, Nettacker adopted Poetry as its package manager instead of the `requirements.txt` file. Poetry simplifies dependency management, handling both the installation of dependencies and packaging more efficiently.

Now, the dependencies for Nettacker are listed in `pyproject.toml`, which is a modern PEP 518 standard.  `pyproject.toml` is also used by Poetry package manager, and the installation process follows a different approach:

 You can install Nettacker directly from PyPI with the command:
 `pip3 install nettacker` 
 or if you have already cloned Nettacker git repo you can run:
 
 `pip install .` 
 
inside the Nettacker folder.


To see the list of command options you can use:

```
nettacker --help 
```

or 

```
nettacker -h
```

### Install Nettacker Using Docker

```
docker pull owasp/nettacker
docker run -it owasp/nettacker /bin/bash
```

For usage instructions and examples please read [Usage.md](Usage.md)

Absolutely—here’s your **complete, clean markdown block** matching the style of your existing file (simple headings, bullet points, code blocks).

👉 **Just paste this at the VERY END of `docs/Installation.md`**


## Who is this for?

OWASP Nettacker is designed for:

* **Security researchers** who want to automate reconnaissance and vulnerability scanning  
* **Developers** who want to test and secure their applications  
* **Beginners** who are learning about penetration testing and security tools  

## Choose the Right Installation Method

You can install OWASP Nettacker in different ways depending on your needs:

* **pip (Recommended for beginners)**  
  Simple and quick setup for immediate use  

* **pipx**  
  Installs Nettacker in an isolated environment without affecting system packages  

* **Git Clone + pip**  
  Best for contributors or users who want the latest source code  

* **Poetry**  
  Useful for developers managing dependencies and working on the project  

* **Docker**  
  Ideal if you don’t want to install dependencies on your system  

## Quick Start (TL;DR)

Run Nettacker quickly with minimal setup:

```

python3 -m venv venv
source venv/bin/activate
pip install nettacker
nettacker --help

```

Example scan:

```

nettacker -i example.com -m port_scan

```

## Environment Setup Best Practices

* Always use a **virtual environment** to avoid dependency conflicts  
* Ensure you are using **Python 3.10 or higher**  
* Keep your tools updated using:
```

pip install --upgrade pip

```
* Avoid mixing global and virtual environment installations  

## Common Setup Mistakes

* Using unsupported Python versions (< 3.10)  
* Forgetting to activate the virtual environment  
* Missing required system dependencies  
* Running commands outside the project directory (when using git clone)  

**Fix:**  
Reinstall dependencies and ensure the correct environment is active.

## Verification Checklist

After installation, verify everything is working:

* Run:
```

nettacker --help

```
or
```

python3 nettacker.py -h

```

* Confirm no errors are shown  
* Check Python version:
```

python3 -V

```
* Ensure environment is activated (if using venv)

## Next Steps

After successful installation:

* Explore usage options in [Usage.md](Usage.md)  
* Run your first scan:
```

nettacker -i example.com -m port_scan

```
* View available modules and commands:
```

nettacker --help

```

This will help you get started quickly with OWASP Nettacker.
