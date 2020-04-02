FROM python:3.8.2-slim-buster

WORKDIR /app

ENV DB_HOST postgresql

COPY ./src/ /app

RUN pip install --upgrade pip && \
    pip install /app/

EXPOSE 8000

CMD gunicorn --bind 0.0.0.0:8000 covitrace_api:app
