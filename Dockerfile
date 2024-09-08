FROM python:3.11.9-slim

RUN mkdir -p .data/results && \
    apt-get update && \
    apt-get install -y gcc libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --upgrade pip poetry

WORKDIR /usr/src/owaspnettacker

COPY .data .data
COPY nettacker nettacker
COPY nettacker.py poetry.lock pyproject.toml README.md ./

RUN poetry install --no-root --without dev --without test

ENV docker_env=true

CMD [ "poetry", "run", "python", "./nettacker.py" ]
