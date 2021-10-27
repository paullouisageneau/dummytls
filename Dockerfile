# syntax=docker/dockerfile:1
FROM python:3.10-slim-bullseye
RUN apt-get update && apt-get install -y certbot
COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt
ENTRYPOINT ["python3", "-m", "dummytls"]
EXPOSE 53
EXPOSE 80
EXPOSE 443

