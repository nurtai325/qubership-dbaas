FROM ghcr.io/netcracker/qubership/core-base:1.0.0
MAINTAINER qubership

ADD ./install /tmp/

RUN chmod +x /tmp/install.sh && /tmp/install.sh
ENTRYPOINT ["/validation.sh"]

USER 1000