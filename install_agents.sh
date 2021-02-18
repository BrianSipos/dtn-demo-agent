#!/bin/bash
# Install local-user services to run on the session bus.
set -e

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

#    multicast:
#        v4sources:
#          - ${IPADDR}

    dtls_enable_tx: False

    mtu_default: 1280
    init_listen:
      - address: ${IPADDR}
      - address: 224.0.0.1
#        multicast_member:
#          - addr: 224.0.0.1

tcpcl:
    log_level: info
    bus_service: dtn.${NODENAME}.tcpcl
    node_id: dtn://${NODENAME}/

    tls_enable: False
    init_listen:
        address: ${IPADDR}

bp:
    log_level: debug
    bus_service: dtn.${NODENAME}.bp
    node_id: dtn://${NODENAME}/

    rx_route_table:
      - eid_pattern: "dtn:~neighbor"
        action: deliver
      - eid_pattern: "dtn://client/.*"
        action: deliver

    tx_route_table:
      - eid_pattern: "dtn:~neighbor"
        next_nodeid: "dtn:~neighbor"
        cl_type: udpcl
        address: 224.0.0.1

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

#    multicast:
#        v4sources:
#          - ${IPADDR}

    dtls_enable_tx: False

    mtu_default: 1280
    init_listen:
      - address: ${IPADDR}
      - address: 224.0.0.1
#        multicast_member:
#          - addr: 224.0.0.1

tcpcl:
    log_level: info
    bus_service: dtn.${NODENAME}.tcpcl
    node_id: dtn://${NODENAME}/

    tls_enable: False
    init_listen:
        address: ${IPADDR}

bp:
    log_level: debug
    bus_service: dtn.${NODENAME}.bp
    node_id: dtn://${NODENAME}/

    rx_route_table:
      - eid_pattern: "dtn:~neighbor"
        action: deliver
      - eid_pattern: "dtn://server/.*"
        action: deliver

    tx_route_table:
      - eid_pattern: "dtn:~neighbor"
        next_nodeid: "dtn:~neighbor"
        cl_type: udpcl
        address: 224.0.0.1

      - eid_pattern: "dtn://client/.*"
        next_nodeid: dtn://client/
        cl_type: udpcl
#        cl_type: tcpcl
        address: 127.0.0.2

        # default route
#      - eid_pattern: ".*"
#        next_nodeid: dtn:none
#        cl_type: udpcl
#       address: 127.0.0.8

EOF

pip3 install --user .
$SYSTEMCTL daemon-reload
for NODE in client server; do
    for SVC in bp udpcl; do
    $SYSTEMCTL restart dtn-${SVC}-agent@${NODE}
    done
done
$SYSTEMCTL status "dtn.slice"
