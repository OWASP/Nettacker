FROM python:3.6-alpine3.8
RUN apk --update add --virtual build-dependencies git gcc musl-dev libffi-dev libxml2-dev libxslt-dev openssl-dev make
WORKDIR /usr/src/owaspnettacker
RUN git clone https://github.com/zdresearch/OWASP-Nettacker.git .
RUN pip install -r requirements.txt
CMD [ "python", "./nettacker.py" ]
