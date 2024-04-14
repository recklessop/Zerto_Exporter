FROM python:3.13.0a6-slim

EXPOSE 9999

WORKDIR /usr/src/app

COPY app/* /usr/src/app/

RUN pip install --no-cache-dir -r requirements.txt
