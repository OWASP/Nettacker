FROM python:2.7-alpine
RUN apk --update add --virtual build-dependencies git gcc musl-dev libffi-dev libxml2-dev libxslt-dev openssl-dev make
WORKDIR /usr/src/owaspnettacker
RUN git clone --depth 1 https://github.com/zdresearch/OWASP-Nettacker.git . && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del build-dependencies && rm -rf /var/cache/apk/*
ENTRYPOINT ["python", "./nettacker.py"]
CMD [ "--help" ]
