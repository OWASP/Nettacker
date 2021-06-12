FROM python:3.9.5
RUN apt update
RUN apt install -y openssl libffi-dev musl-dev make gcc git curl librtmp* libxml2-dev libxslt-dev
WORKDIR /usr/src/owaspnettacker
COPY . .
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
RUN pip3 install -r requirements-dev.txt
CMD [ "python3", "./nettacker.py" ]
