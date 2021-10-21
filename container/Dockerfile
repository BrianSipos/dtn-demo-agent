FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

# Use systemd as container executive
RUN --mount=type=cache,target=/var/cache/apt apt-get update && \
    apt-get install -yq systemd systemd-sysv && \
    systemctl mask getty-static.service getty@tty1.service systemd-logind.service && \
    systemctl disable ssh
CMD [ "/sbin/init" ]

RUN --mount=type=cache,target=/var/cache/apt apt-get update && \
    apt-get install -yq git python3-pip \
    python3-setuptools python3-cairo python3-gi python3-dbus dbus
# Manual pycose separate from pip
#RUN --mount=type=cache,target=/root/.cache pip3 install git+https://github.com/TimothyClaeys/pycose.git@master

COPY src/ /root/agent/src/
COPY setup.py /root/agent/
RUN --mount=type=cache,target=/root/.cache pip3 install /root/agent

COPY container/dbus.conf /etc/dbus-1/system.d/org.ietf.dtn.conf
COPY container/*.service container/*.slice /usr/local/lib/systemd/system/

# This will require file /etc/xdg/dtn/node.yaml
RUN systemctl enable dtn-bp-agent@node && \
    systemctl enable dtn-tcpcl-agent@node && \
    systemctl enable dtn-udpcl-agent@node
