FROM python:3.12.0a2-slim
RUN apt update
WORKDIR /usr/src/owaspnettacker
COPY . .
RUN mkdir -p .data/results
RUN apt-get update
RUN apt-get install -y $(cat requirements-apt-get.txt)
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
RUN pip3 install -r requirements-dev.txt
ENV docker_env=true
CMD [ "python3", "./nettacker.py" ]
