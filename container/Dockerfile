FROM ubuntu:22.04 AS systemd-base
ENV DEBIAN_FRONTEND="noninteractive"

ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt
ENV PIP_DEFAULT_TIMEOUT=300
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# Distro upgrade for security patches
RUN apt-get update && apt-get upgrade -y

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
    apt-get install -yq git python3-pip python3-venv pkg-config \
    python3-setuptools \
    python3-cairo \
    python3-gi \
    python3-dbus dbus \
    rustc cargo
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --upgrade pip && \
    pip3 install pip-tools maturin

COPY pyproject.toml /root/agent/
#RUN --mount=type=cache,target=/root/.cache/pip \
#    cd /root/agent && \
#    pip-compile pyproject.toml && \
#    pip3 install -r requirements.txt
COPY src/ /root/agent/src/
RUN --mount=type=cache,target=/root/.cache/pip pip3 install /root/agent

COPY container/dbus.conf /etc/dbus-1/system.d/org.ietf.dtn.conf
COPY container/*.service container/*.slice /usr/local/lib/systemd/system/

# This will require file /etc/xdg/dtn/node.yaml
RUN systemctl enable dtn-bp-agent@node && \
    systemctl enable dtn-tcpcl-agent@node && \
    systemctl enable dtn-udpcl-agent@node
