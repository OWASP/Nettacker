FROM python:3.11.10-slim

RUN apt-get update && \
    apt-get install -y gcc libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --upgrade pip poetry

WORKDIR /usr/src/owaspnettacker

COPY nettacker nettacker
COPY nettacker.py poetry.lock pyproject.toml README.md ./

RUN poetry install --no-cache --no-root --without dev --without test

ENV docker_env=true

CMD [ "poetry", "run", "python", "./nettacker.py" ]
