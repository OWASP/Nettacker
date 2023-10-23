FROM python:3.11.6-slim

WORKDIR /usr/src/owaspnettacker

COPY . .

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p .data/results && \
    apt-get update && \
    apt-get install -y $(cat requirements-apt-get.txt) && \
    pip3 install --upgrade pip && \
    pip3 install -r requirements.txt && \
    pip3 install -r requirements-dev.txt && \
    apt-get clean && \
    rm -rf /root/.cache/* && \
    rm -rf /var/lib/apt/lists/*

ENV docker_env=true

EXPOSE 5000

CMD ["python3", "./nettacker.py"]
