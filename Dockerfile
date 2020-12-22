FROM python:2.7
RUN apt update
RUN apt install -y openssl libffi-dev musl-dev make gcc git curl librtmp* libxml2-dev libxslt-dev
WORKDIR /usr/src/owaspnettacker
COPY . .
RUN pip install -r requirements.txt
CMD [ "python", "./nettacker.py" ]
