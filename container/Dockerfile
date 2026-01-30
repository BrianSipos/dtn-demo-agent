FROM ubuntu:24.04 AS systemd-base
ENV DEBIAN_FRONTEND="noninteractive"

ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt
ENV PIP_DEFAULT_TIMEOUT=300
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# Distro upgrade for security patches
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get upgrade -y

# Use systemd as top-level process
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y systemd systemd-sysv
RUN systemctl mask systemd-logind && \
    systemctl mask console-getty && \
    systemctl disable getty@tty1 && \
    systemctl disable apt-daily.timer apt-daily-upgrade.timer && \
    systemctl disable systemd-timesyncd && \
    systemctl disable systemd-networkd && \
    echo "MulticastDNS=no" >>/etc/systemd/resolved.conf
CMD [ "/sbin/init" ]

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -yq \
        git python3-pip python3-venv python3-wheel python3-setuptools \
        libdbus-glib-1-dev libcairo2-dev libgirepository-2.0-dev \
        pkg-config \
        dbus 
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages pip-tools maturin

# Work-around python3-dtls requiring openssl-1.1 but not available on 24.04
#RUN --mount=type=cache,target=/var/cache/apt apt-get update && \
#    apt-get install -yq curl && \
#    curl -svLO http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.23_amd64.deb && \
#    dpkg -i libssl1.1_*_amd64.deb && \
#    apt-get -fy install && \
#    rm libssl1.1_*_amd64.deb

COPY pyproject.toml /usr/local/src/agent/
COPY src/ /usr/local/src/agent/src/
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages /usr/local/src/agent

COPY container/dbus.conf /etc/dbus-1/system.d/org.ietf.dtn.conf
COPY container/*.service container/*.slice /usr/local/lib/systemd/system/

# This will require file /etc/xdg/dtn/node.yaml
RUN systemctl enable dtn-bp-agent@node && \
    systemctl enable dtn-tcpcl-agent@node && \
    systemctl enable dtn-udpcl-agent@node
