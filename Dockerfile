FROM python:3.10.0rc2
RUN apt update
WORKDIR /usr/src/owaspnettacker
COPY . .
RUN mkdir -p .data/results
RUN apt-get update
RUN apt-get install -y < requirements-apt-get.txt
RUN pip3 install --upgrade pip 
# Below command is only used here separately as it will show error if placed in requirements.txt 
RUN pip3 install mysql-connector-python  
RUN pip3 install -r requirements.txt
RUN pip3 install -r requirements-dev.txt
ENV docker_env=true
CMD [ "python3", "./nettacker.py" ]
