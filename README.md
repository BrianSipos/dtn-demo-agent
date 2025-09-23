# Python implementation of basic BPv7-related protocols

The demo TCPCL agent implements the corresponding specification draft.
A TCPCL agent is symmetric, there is no notion of a single agent being a "server" or a "client".
The demo agent hosted here has an optional startup action, which is to either listen on an address+port (act as a passive node in a TCPCL session) or to connect to an address+port (act as an active node in a TCPCL session).
Once the agent is started, regardless of which or if a startup action was given, the agent can be commanded via D-Bus to listen/connect for later sessions or to transport bundles over existing sessions.

## Starting the Agent

All of these commands require either a local installation of the python packages, or using an environment such as
```
PYTHONPATH=demo-agent/src
```

When running local--local testing on loopback device "lo" alternate address assignments must be made similarly to:
```
sudo ip -4 addr add 127.0.0.2/8 dev lo
sudo ip -4 addr add 127.0.0.3/8 dev lo
sudo ip -6 addr add ::2/128 dev lo
ip link set dev lo multicast on
```

A pair of TCPCL entities can be created with commands:
```
python3 -m tcpcl.agent --config-file=server.yaml
python3 -m tcpcl.agent --config-file=client.yaml
```

It is also possible for either the active- or passive-side agent to log TLS ephemeral key data using the `SSLKEYLOGFILE` environment variable to specify a key material log file (in an indentical way to how Firefox/Chrome browsers use it).

## Commanding the Agent
The agent can be accessed via D-Bus based on the `bus-service` name given on the command line.

### Agent Interface

The agent itself is accessible via the object `/org/ietf/dtn/tcpcl/Agent` with interface `org.ietf.dtn.tcpcl.Agent`.

The methods in this interface are:

- `listen(address, port)` to cause the agent to listen on a given port.
- `listen_stop(address, port)` to cause the agent to stop listening.
- `connect(address, port)` to cause the agent to attempt a connection to a peer.
- `shutdown()` causes any open sessions to be terminated, which itself may wait on in-progress transfers to complete. The return value is `True` if the agent stopped immediately, or `False` if sessions are being waited on before stopping.
- `stop()` forces the process to exit immediately and not wait.

The signals in this interface are:

- `connection_opened(path)` is emitted when a new TCP connection is opened and session negotiation begins. This does not mean the session is established and ready for use, just that a session may be established on the new connection.
- `connection_closed(path)` is emitted when a TCP connection is closed.

### Session Interface

Each established session is accessible via the object `/org/ietf/dtn/tcpcl/Contact{N}`, where `{N}` is some unique identifier number, with interface `org.ietf.dtn.tcpcl.Contact`.

Notable methods in this interface are:

- `is_sess_idle()` which returns true when the session is established, ready for use, and no messages are being sent or recevied.
- `is_secure()` which returns true if TLS is used to secure the session.
- `send_bundle_get_queue()` which returns Transfer IDs which are queued for sending.
- `send_bundle_file(filepath)` which queues transfer of a file directly from the filesystem. The agent must have sufficient permission to read from the file. The return value is the new Transfer ID.
- `send_bundle_data(bytes)` which queues transfer of data from the message itself. The return value is the new Transfer ID.
- `recv_bundle_get_queue()` which returns the Transfer IDs which have been received and are ready.
- `recv_bundle_pop_file(bid, filepath)` which takes a received transfer directly into the filesystem. The `bid` argument is the Transfer ID to pop. The agent must have sufficient permission to write to the file.
- `recv_bundle_pop_data(bid)` which takes a received transfer and returns its contents as a byte array. The `bid` argument is the Transfer ID to pop. The return value is the transfer data itself.
- `terminate(reason_code)` which performs the session termination procedure, which waits for any in-progress transfers to complete then closes the TCP connection.
- `close()` which closes the TCP connection immediately.

Files can be sent with commands similar to:
```
dbus-send --print-reply --dest=tcpcl.Client /org/ietf/dtn/tcpcl/Contact0 org.ietf.dtn.tcpcl.Contact.send_bundle_file string:"/etc/hostname"
```

Files can be popped out of the agent after reception with commands similar to:
```
dbus-send --print-reply --dest=tcpcl.Server /org/ietf/dtn/tcpcl/Contact0 org.ietf.dtn.tcpcl.Contact.recv_bundle_get_queue
```
to get the received Transfer ID, and
```
dbus-send --print-reply --dest=tcpcl.Server /org/ietf/dtn/tcpcl/Contact0 org.ietf.dtn.tcpcl.Contact.recv_bundle_pop_file string:1 string:/tmp/dest
```
to actually save the received bundle.

## Network Sequencing Tests

There is a full end-to-end agent test which can be run by the command:
```
python3 -m tcpcl.test.bundlegen <gentype> <gencount>
```
where `gentype` of "fullvalid" generates valid BPv7 test bundles, and `gencount` is the total number of bundles to generate and transfer.

# Containerized nodes

The `run.py` commands use the environment `DOCKER` to control the container tool.
For example in fedora use the environment `DOCKER="sudo podman"`.

To install prerequisites for python run:
```
pip3 install '.[container]'
```

To initialize and start a set of containers:
```
./container/run.py --config container/example.yaml act pkigen build start ready
```

To observe the log of one of the nodes:
```
./container/run.py --config container/example.yaml exec node000 -- journalctl -f
```

To capture traffic across container networks, run similar to:
```
wireshark -i br-dtnA -i br-dtnB -f 'port 4556 or port 1113 or icmp' -Y 'bpv7' -k
```

To call DBus methods in one of the nodes:
```
./container/run.py --config container/example.yaml exec node000 dbus-send --system --print-reply --dest=org.ietf.dtn.node.udpcl /org/ietf/dtn/udpcl/Agent org.ietf.dtn.udpcl.Agent.pmtud_start string:node002. uint16:4556
```

## ACME Validation Prototype

To perform an ACME validation exchange between two nodes run the script:
```
 node000 dbus-send --system --print-reply --dest=org.ietf.dtn.node.bp /org/ietf/dtn/bp/app/admin org.ietf.dtn.bp.admin.start_expect_acme_request string:"dDtaviYTPUWFS3NK37YWfQ" string:"tPUZNY4ONIk6LxErRFEjVw" string:"LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ" && \
docker container exec -it node001 dbus-send --system --print-reply --dest=org.ietf.dtn.node.bp /org/ietf/dtn/bp/app/admin org.ietf.dtn.bp.admin.send_acme_request string:"dtn://node000/" string:"dDtaviYTPUWFS3NK37YWfQ" string:"tPUZNY4ONIk6LxErRFEjVw" string:"p3yRYFU4KxwQaHQjJ2RdiQ" string:"LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ" && \
docker container exec -it node000 dbus-send --system --print-reply --dest=org.ietf.dtn.node.bp /org/ietf/dtn/bp/app/admin org.ietf.dtn.bp.admin.stop_expect_acme_request string:"dDtaviYTPUWFS3NK37YWfQ"
```

## SAFE Prototype

To initiate a primary SA with another SAFE endpoint run:
```
./container/run.py --config container/example-safe.yaml exec node000 -- dbus-send --system --print-reply --dest=org.ietf.dtn.node.bp /org/ietf/dtn/bp/app/safe org.ietf.dtn.bp.safe.start string:dtn://node001/safe

```

# Wireshark Protocols and Dissectors

The wireshark modules have been moved into separate project [dtn-wireshark](https://github.com/BSipos-RKF/dtn-wireshark).
