FROM python:3.11.1-slim

EXPOSE 9999

WORKDIR /usr/src/app

COPY app/* /usr/src/app/

RUN pip install --no-cache-dir -r requirements.txt
