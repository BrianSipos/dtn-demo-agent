#!/bin/bash
# Install local-user services to run on the session bus.
set -e
SELFDIR=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

SYSTEMCTL="systemctl --user"

mkdir -p "$HOME/.config/systemd/user"
cat <<EOF >"$HOME/.config/systemd/user/dtn.slice"
[Slice]
EOF
cat <<EOF >"$HOME/.config/systemd/user/dtn-udpcl-agent@.service"
[Unit]
Description=DTN UDPCL Agent for %i
AssertPathExists=$HOME/.local/bin/udpcl-agent
After=syslog.target network-online.target

[Service]
Slice=dtn.slice
Type=dbus
ExecStart=$HOME/.local/bin/udpcl-agent --config $HOME/.config/dtn/%i.yaml
BusName=dtn.%i.udpcl

[Install]
WantedBy=dtn-bp-agent@%i.service
EOF
cat <<EOF >"$HOME/.config/systemd/user/dtn-tcpcl-agent@.service"
[Unit]
Description=DTN TCPCL Agent for %i
AssertPathExists=$HOME/.local/bin/tcpcl-agent
After=syslog.target network-online.target

[Service]
Slice=dtn.slice
Type=dbus
ExecStart=$HOME/.local/bin/tcpcl-agent --config $HOME/.config/dtn/%i.yaml
BusName=dtn.%i.tcpcl

[Install]
WantedBy=dtn-bp-agent@%i.service
EOF
cat <<EOF >"$HOME/.config/systemd/user/dtn-bp-agent@.service"
[Unit]
Description=DTN BP Agent for %i
AssertPathExists=$HOME/.local/bin/bp-agent
After=syslog.target network-online.target
Wants=dtn-udpcl-agent@%i.service dtn-tcpcl-agent@%i.service

[Service]
Slice=dtn.slice
Type=dbus
ExecStart=$HOME/.local/bin/bp-agent --config $HOME/.config/dtn/%i.yaml
BusName=dtn.%i.bp

[Install]
WantedBy=multi-user.target
EOF

NODENAME=client
IPADDR="127.0.0.2"
mkdir -p "$HOME/.config/dtn"
cat <<EOF >"$HOME/.config/dtn/client.yaml"
udpcl:
    log_level: info
    bus_service: dtn.${NODENAME}.udpcl
    node_id: dtn://${NODENAME}/

    dtls_enable_tx: False
    dtls_ca_file: ${SELFDIR}/testpki/ca.crt
    dtls_key_file: ${SELFDIR}/testpki/client-transport.key
    dtls_cert_file: ${SELFDIR}/testpki/client-transport.crt

    default_tx_address: ${IPADDR}
    mtu_default: 1280

#    init_listen:
#      - address: ${IPADDR}
#      - address: 224.0.0.1
#        multicast_member:
#          - addr: 224.0.0.1
    polling:
      - address: 127.0.0.3
        interval_ms: 10000

tcpcl:
    log_level: info
    bus_service: dtn.${NODENAME}.tcpcl
    node_id: dtn://${NODENAME}/

    tls_enable: False
    tls_ca_file: ${SELFDIR}/testpki/ca.crt
    tls_key_file: ${SELFDIR}/testpki/client-transport.key
    tls_cert_file: ${SELFDIR}/testpki/client-transport.crt

#    init_listen:
#        address: ${IPADDR}

bp:
    log_level: info
    bus_service: dtn.${NODENAME}.bp
    node_id: dtn://${NODENAME}/

    verify_ca_file: ${SELFDIR}/testpki/ca.crt
    sign_key_file: ${SELFDIR}/testpki/client-sign.key
    sign_cert_file: ${SELFDIR}/testpki/client-sign.crt

    rx_route_table:
      - eid_pattern: "dtn://client/.*"
        action: deliver

    tx_route_table:
      - eid_pattern: "dtn://server/.*"
        next_nodeid: dtn://server/
        cl_type: udpcl
#        cl_type: tcpcl
        address: 127.0.0.3

        # default route
      - eid_pattern: ".*"
        next_nodeid: dtn://server/
        cl_type: udpcl
        address: 127.0.0.3

nmp:
    bus_service: dtn.${NODENAME}.nmp
EOF

NODENAME=server
IPADDR="127.0.0.3"
mkdir -p "$HOME/.config/dtn"
cat <<EOF >"$HOME/.config/dtn/server.yaml"
udpcl:
    log_level: info
    bus_service: dtn.${NODENAME}.udpcl
    node_id: dtn://${NODENAME}/

    dtls_enable_tx: False
    dtls_ca_file: ${SELFDIR}/testpki/ca.crt
    dtls_key_file: ${SELFDIR}/testpki/server-transport.key
    dtls_cert_file: ${SELFDIR}/testpki/server-transport.crt

    default_tx_address: ${IPADDR}
    mtu_default: 1280
    init_listen:
      - address: ${IPADDR}
      - address: 224.0.0.1
#        multicast_member:
#          - addr: 224.0.0.1

tcpcl:
    log_level: warn
    bus_service: dtn.${NODENAME}.tcpcl
    node_id: dtn://${NODENAME}/

    tls_enable: False
    tls_ca_file: ${SELFDIR}/testpki/ca.crt
    tls_key_file: ${SELFDIR}/testpki/server-transport.key
    tls_cert_file: ${SELFDIR}/testpki/server-transport.crt

    init_listen:
        address: ${IPADDR}

bp:
    log_level: info
    bus_service: dtn.${NODENAME}.bp
    node_id: dtn://${NODENAME}/

    verify_ca_file: ${SELFDIR}/testpki/ca.crt
    sign_key_file: ${SELFDIR}/testpki/server-sign.key
    sign_cert_file: ${SELFDIR}/testpki/server-sign.crt

    rx_route_table:
      - eid_pattern: "dtn://server/.*"
        action: deliver

    tx_route_table:
      - eid_pattern: "dtn:~neighbor"
        next_nodeid: "dtn:~neighbor"
        cl_type: udpcl
        address: 224.0.0.1
#    multicast:
#        v4sources:
#          - ${IPADDR}

#      - eid_pattern: "dtn://client/.*"
#        next_nodeid: dtn://client/
#        cl_type: udpcl
#        address: 127.0.0.2

        # default route
#      - eid_pattern: ".*"
#        next_nodeid: dtn:none
#        cl_type: udpcl
#       address: 127.0.0.8

EOF

pip3 install --user .
$SYSTEMCTL daemon-reload
for NODE in server client; do
    for SVC in udpcl tcpcl bp; do
    $SYSTEMCTL restart dtn-${SVC}-agent@${NODE}
    done
done
$SYSTEMCTL status "dtn.slice"
