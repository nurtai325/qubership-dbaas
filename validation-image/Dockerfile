FROM ghcr.io/netcracker/qubership/core-base:1.0.0
MAINTAINER qubership

RUN apk add --no-cache zip unzip jq postgresql wget curl bash python3 py3-pycryptodome && \
    curl -L "https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl" -o /bin/kubectl && \
    chmod +x /bin/kubectl

COPY install/validation.sh /validation.sh
COPY install/prepare-database.sh /prepare-database.sh

USER 1000
ENTRYPOINT ["/validation.sh"]

