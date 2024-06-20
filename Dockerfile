FROM python:3.11.9-slim
RUN apt update
WORKDIR /usr/src/owaspnettacker
COPY . .
RUN mkdir -p .data/results
RUN apt-get update && apt-get install -y $(cat requirements-apt-get.txt) && pip3 install --upgrade pip
RUN pip3 install --no-cache-dir -r requirements.txt -r requirements-dev.txt
ENV docker_env=true
CMD [ "python3", "./nettacker.py" ]