FROM python:2.7-alpine
RUN apk add --no-cache python pkgconfig python-dev openssl-dev libffi-dev musl-dev make gcc
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD [ "python", "./nettacker.py", "--help" ]