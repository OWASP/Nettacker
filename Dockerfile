FROM python:3.11.0rc2
WORKDIR /usr/src/owaspnettacker
COPY . .
RUN mkdir -p .data/results
RUN apt-get update
RUN apt-get install -y < requirements-apt-get.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
RUN pip3 install -r requirements-dev.txt
RUN wget https://github.com/rofl0r/proxychains-ng/archive/refs/tags/v4.16.zip
RUN unzip v4.16.zip && cd proxychains-ng-4.16 && ./configure && make && make install && cd ..
ENV docker_env=true
CMD [ "python3", "./nettacker.py" ]
