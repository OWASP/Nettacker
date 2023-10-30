FROM python:3.11.6-slim

RUN mkdir -p .data/results
RUN apt-get update
RUN apt-get install -y gcc libssl-dev
RUN pip3 install --upgrade pip nettacker

WORKDIR /usr/src/owaspnettacker
RUN mkdir -m 700 .data
COPY src/nettacker/api/run.py .

ENV docker_env=true

CMD ["python3", "run.py", "--start-api", "--api-host", "0.0.0.0"]
