FROM python:3.12-slim-bookworm

ARG DEBIAN_FRONTED=noninteractive
ARG PYTHON=python3
ENV CONTAINER=1

WORKDIR /home/app
RUN apt-get -y update
RUN apt -y install wget unzip curl
RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN apt -y install ./google-chrome-stable_current_amd64.deb
RUN wget -O /tmp/chromedriver.zip http://chromedriver.storage.googleapis.com/` curl -sS chromedriver.storage.googleapis.com/LATEST_RELEASE`/chromedriver_linux64.zip
RUN unzip /tmp/chromedriver.zip chromedriver -d /home/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY /noip-renew.py /home/loblab/
ENTRYPOINT ["python3", "/home/loblab/noip-renew.py"]

COPY /noip-renew.py /home/app/
ENTRYPOINT ["python3", "/home/app/noip-renew.py"]