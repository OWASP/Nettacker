# Installation

You have multiple options for installing OWASP Nettacker, each with specific instructions provided in dedicated sections below. 

PLEASE NOTE: OWASP Nettacker currently supports Python 3.11 - 3.12. Work to make Nettacker compatible with
later Python versions is ongoing. Because newer operating systems may provide an
unsupported Python version by default, the examples below use
[pyenv](https://github.com/pyenv/pyenv) to install and select Python 3.11.15 explicitly.


Nettacker can run natively on Linux, macOS and FreeBSD. Users of other operating systems
can run Nettacker with Docker. Although native Windows support was initially dropped, we
are currently working towards reintroducing it in future versions.

> [!NOTE]
> Starting with Nettacker 0.3.1, Python 2 and Python versions earlier than 3.10 are no
> longer supported. For those Python versions, use the legacy
> [Nettacker 0.0.2 release](https://github.com/OWASP/Nettacker/releases/tag/0.0.2).

## Prerequisites

Nettacker depends on system libraries and build tools. On Debian or Ubuntu you can install them
with:

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential curl git libbz2-dev libcurl4-openssl-dev libffi-dev liblzma-dev \
    libncursesw5-dev libpq-dev libreadline-dev librtmp-dev libsqlite3-dev libssl-dev \
    libxml2-dev libxmlsec1-dev tk-dev xz-utils zlib1g-dev
```

`libpq-dev` is only required when using PostgreSQL. Other Linux distributions and macOS
provide equivalent packages through their package managers.

## Install Python 3.11.15 with pyenv

Install pyenv by following its
[installation instructions](https://github.com/pyenv/pyenv#installation), including the
shell setup for your platform. Then open a new terminal and run:

```bash
pyenv install 3.11.15
"$(pyenv prefix 3.11.15)/bin/python" --version
```

The final command should print `Python 3.11.15`. When working in a dedicated directory or
a cloned Nettacker repository, use the following command to select it automatically
whenever you enter that directory and pyenv's shell integration is active:

```bash
pyenv local 3.11.15
```

Choose one of the installation methods below.

## Install from source with Poetry

Install [Poetry](https://python-poetry.org/docs/#installation) if it is not already
available. One option is to install Poetry with pipx:

```bash
pipx install poetry
```

Clone Nettacker, select Python 3.11.15, and tell Poetry to create its environment with that
interpreter:

```bash
git clone https://github.com/OWASP/Nettacker.git --depth 1
cd Nettacker
pyenv local 3.11.15
poetry env use "$(pyenv prefix 3.11.15)/bin/python"
poetry install
poetry run nettacker --help
```

Run Nettacker through Poetry while working in the repository:

```bash
poetry run nettacker --show-all-modules
poetry run nettacker --help
```

Only scan systems that you own or are authorized to test.

## Install from PyPI with pip and venv

Create a project directory, select Python 3.11.15, and create an isolated virtual
environment. If `.venv` already exists, rename or remove it first because creating a venv
does not replace an existing environment's Python interpreter:

```bash
mkdir nettacker-env
cd nettacker-env
pyenv local 3.11.15
"$(pyenv prefix 3.11.15)/bin/python" -m venv .venv
. .venv/bin/activate
python --version
python -m pip install --upgrade pip
python -m pip install nettacker
nettacker --help
```

The version check must print `Python 3.11.15`. The explicit interpreter path ensures that
the virtual environment uses Python 3.11.15 even if pyenv's shims are not active.

Activate the environment before using Nettacker in a new terminal:

```bash
cd nettacker-env
. .venv/bin/activate
nettacker --show-all-modules
```

Leave the virtual environment with `deactivate`.

To install the current source tree with pip instead of installing the PyPI release:

```bash
git clone https://github.com/OWASP/Nettacker.git --depth 1
cd Nettacker
pyenv local 3.11.15
"$(pyenv prefix 3.11.15)/bin/python" -m venv .venv
. .venv/bin/activate
python --version
python -m pip install --upgrade pip
python -m pip install .
nettacker --help
```

## Install from PyPI with pipx

pipx installs command-line applications into isolated environments. Install
[pipx](https://pipx.pypa.io/stable/installation/) with your operating system's package
manager, then install Nettacker using the Python 3.11.15 interpreter managed by pyenv:

```bash
pipx ensurepath
pipx install --python "$(pyenv prefix 3.11.15)/bin/python" nettacker
nettacker --help
```

Open a new terminal after `pipx ensurepath` if `nettacker` is not immediately available.
Verify the interpreter used by the pipx environment with:

```bash
pipx runpip nettacker debug --verbose
```

The output should report Python 3.11.15. Upgrade or remove the installation with:

```bash
pipx upgrade nettacker
pipx uninstall nettacker
```

## Why there is no requirements.txt

Starting with version 0.4.0, Nettacker moved from a traditional `requirements.txt` file to
Poetry for dependency management and packaging. The project dependencies and package
metadata are now declared in `pyproject.toml`, the modern Python packaging standard used
by Poetry and pip.

After installation, display the available command-line options with:

```bash
nettacker --help
```

## Install with Docker

```bash
docker run --rm owasp/nettacker --help
```

This runs the latest released version. To try the current development version, run:

```bash
docker run --rm owasp/nettacker:dev --help
```

The `dev` image is built from the latest changes on the `master` branch after the Docker
tests pass. It may contain features and fixes that have not been released yet and can be
less stable than the standard image (with the `latest` tag).

For command examples, see the [usage guide](Usage.md).
