# syntax=docker/dockerfile:1
FROM python:3.10-slim-bullseye
RUN apt-get update && apt-get install -y certbot
COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt
RUN printf '#!/bin/sh\ncd /app && python -m dummytls "$@"\n' > /usr/local/bin/dummytls && chmod +x /usr/local/bin/dummytls
CMD dummytls
EXPOSE 53
EXPOSE 80
EXPOSE 443

