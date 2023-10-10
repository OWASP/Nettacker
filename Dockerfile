FROM python:3.11.5-slim

WORKDIR /usr/src/owaspnettacker

COPY . .

RUN <<EOL
mkdir -p .data/results
apt-get update
apt-get install -y $(cat requirements-apt-get.txt)
pip3 install --upgrade pip
pip3 install -r requirements.txt
pip3 install -r requirements-dev.txt
EOL

ENV docker_env=true

CMD [ "python3", "./nettacker.py" ]
