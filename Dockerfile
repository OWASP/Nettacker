FROM python:3.9.5
RUN apt update
WORKDIR /usr/src/owaspnettacker
COPY . .
RUN cat requirements-apt-get.txt | apt install -y
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
RUN pip3 install -r requirements-dev.txt
CMD [ "python3", "./nettacker.py" ]
