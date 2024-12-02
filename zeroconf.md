Start the containers with:
```
./container/run.py --config container/example-zeroconf.yaml act pkigen build start ready
```
which will cause the mDNS offer and enumeration after a few (under 10) seconds.

The traffic can be monitored with:
```
wireshark -i br-dtnA -i br-dtnB -f 'port 4556 or port 1113 or port 5353' -Y tcpcl -k
```

Send a ping to exercise the routing with:
```
docker container exec -it node000 dbus-send --system --print-reply --dest=org.ietf.dtn.node.bp /org/ietf/dtn/bp/Agent org.ietf.dtn.bp.Agent.ping string:"dtn://node002/srv" int32:32
```
