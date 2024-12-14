FROM alpine:3.21.0

USER root

COPY scripts scripts
COPY install /usr/local

WORKDIR scripts

RUN ./deploy.sh
