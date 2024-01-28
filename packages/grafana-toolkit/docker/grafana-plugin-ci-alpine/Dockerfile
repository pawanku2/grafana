FROM alpine:3.18.6

USER root

COPY scripts scripts
COPY install /usr/local

WORKDIR scripts

RUN ./deploy.sh
