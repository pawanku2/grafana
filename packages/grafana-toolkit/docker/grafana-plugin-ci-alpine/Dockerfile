FROM alpine:3.16.9

USER root

COPY scripts scripts
COPY install /usr/local

WORKDIR scripts

RUN ./deploy.sh
