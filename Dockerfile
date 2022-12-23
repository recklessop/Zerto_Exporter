FROM python:3.12.0a3-slim

EXPOSE 9999

WORKDIR /usr/src/app

COPY app/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt