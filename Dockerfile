FROM python:3.11.9-slim
RUN apt update
WORKDIR /usr/src/owaspnettacker
COPY . .
RUN mkdir -p .data/results
RUN apt-get update
RUN apt-get install -y gcc libssl-dev
RUN pip3 install --upgrade poetry
RUN python -m poetry install
ENV docker_env=true
CMD [ "poetry", "run", "python", "./nettacker.py" ]
