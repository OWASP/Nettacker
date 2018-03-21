FROM python:2.7-alpine
RUN apk add --no-cache python pkgconfig python-dev openssl-dev libffi-dev musl-dev make gcc git curl-dev librtmp
WORKDIR /usr/src/owaspnettacker
RUN git clone https://github.com/viraintel/OWASP-Nettacker.git .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install scapy
RUN apk del --purge musl-dev gcc make
CMD [ "python", "./nettacker.py" ]
