FROM fedora:32

RUN dnf -y install git python3-pip python3-setuptools \
    python3-gobject-base python3-dbus dbus-tools && \
    yum clean all

RUN pip3 install git+https://github.com/BSipos-RKF/pycose.git@develop

COPY src/ /root/agent/src/
COPY setup.py /root/agent/
RUN pip3 install /root/agent

COPY container/dbus.conf /etc/dbus-1/system.d/org.ietf.dtn.conf
COPY container/*.service container/*.slice /etc/systemd/system/

# This will require file /etc/xdg/dtn/node.yaml
RUN systemctl enable dtn-bp-agent@node && \
    systemctl enable dtn-udpcl-agent@node

CMD [ "/sbin/init" ]
