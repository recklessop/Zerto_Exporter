FROM python:3.11.0rc2-slim

EXPOSE 9999

WORKDIR /usr/src/app

COPY app/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt