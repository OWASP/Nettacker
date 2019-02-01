FROM ubuntu
RUN apt update
RUN apt install -y python python-pip python-dev openssl libffi-dev musl-dev make gcc git curl librtmp* libxml2-dev libxslt-dev
WORKDIR /usr/src/owaspnettacker
RUN git clone https://github.com/zdresearch/OWASP-Nettacker.git .
RUN cat requirements.txt | xargs -n 1 pip install
CMD [ "python", "./nettacker.py" ]
