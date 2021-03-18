''' Application layer adaptors.
'''
import cbor2
from dataclasses import dataclass, field, fields
import datetime
import dbus.service
import enum
from gi.repository import GLib as glib
import ipaddress
import logging
import psutil
import socket
from typing import List

from scapy_cbor.util import encode_diagnostic
from bp.config import TxRouteItem
from bp.encoding import (
    AbstractBlock, PrimaryBlock, CanonicalBlock,
)
from bp.util import BundleContainer, ChainStep
from bp.app.base import app, AbstractApplication

LOGGER = logging.getLogger(__name__)


class MsgKeys(enum.IntEnum):
    MSG_TYPE = 1

    HELLO_VALIDITY_TIME = -1
    HELLO_INTERVAL_TIME = -2
    HELLO_CLSET = -5
    HELLO_NODESET = -3
    HELLO_PEERSET = -6


@enum.unique
class MsgType(enum.IntEnum):
    HELLO = 1


class ClKeys(enum.IntEnum):
    CL_TYPE = 1
    DNSNAME = 2
    ADDR = 3
    PORT = 4
    REQ_SEC = 5


@enum.unique
class ClType(enum.IntEnum):
    TCPCL = 1
    UDPCL = 2


@enum.unique
class LinkStatus(enum.IntEnum):
    HEARD = 1
    SYMMETRIC = 2
    LOST = 3


@dataclass
class OneHopNeighbor(object):
    ''' Discovered neighbor
    '''

    #: The reassembled bundle ident
    node_id: str = ''
    #: Time at which this data becomes invalid
    valid_until = None
    #: Latest inferred status
    link_status: LinkStatus = None
    #: List of TX routes reported for this node
    tx_routes: List[TxRouteItem] = field(default_factory=list)


@app('nmp')
class Nmp(AbstractApplication):
    ''' Neighbor messaging protocol.
    '''

    #: Interface name
    DBUS_IFACE = 'org.ietf.dtn.bp.nmp'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._config = None
        self._last_hello = None
        self._hello_min_intvl = None
        self._one_hop = {}

    def load_config(self, config):
        super().load_config(config)
        self._config = config

        self._hello_min_intvl = datetime.timedelta(seconds=1)

        if False:
            hello_intvl = int(10e3)
            LOGGER.info('Sending HELLO at interval %d ms', hello_intvl)
            glib.timeout_add(hello_intvl, self._timer_hello)
            #glib.idle_add(self._timer_hello)

    def add_chains(self, rx_chain, tx_chain):
        rx_chain.append(ChainStep(
            order=-1,
            name='NMP routing',
            action=self._rx_route
        ))
        rx_chain.append(ChainStep(
            order=30,
            name='NMP handling',
            action=self._recv_bundle
        ))
        tx_chain.append(ChainStep(
            order=-1,
            name='NMP routing',
            action=self._tx_route
        ))

    def _rx_route(self, ctr):
        eid = ctr.bundle.primary.destination
        if eid == 'dtn:~neighbor':
            ctr.record_action('deliver')

    def _recv_bundle(self, ctr):
        if not self._recv_for(ctr, 'dtn:~neighbor'):
            return

        msg = cbor2.loads(ctr.block_num(1).getfieldval('btsd'))
        LOGGER.info('Message RX: %s', encode_diagnostic(msg))

        msg_type = msg[MsgKeys.MSG_TYPE]
        if msg_type == MsgType.HELLO:
            pri_blk = ctr.bundle.primary

            node_id = pri_blk.source
            neighbor = self._one_hop.get(node_id)
            if not neighbor:
                neighbor = OneHopNeighbor(
                    node_id=node_id,
                )
                self._one_hop[node_id] = neighbor

            # at least this much is known, for now
            neighbor.link_status = LinkStatus.HEARD

            valid_ms = msg.get(MsgKeys.HELLO_VALIDITY_TIME)
            if valid_ms is not None and pri_blk.create_ts.dtntime:
                neighbor.valid_until = pri_blk.create_ts.dtntime + datetime.timedelta(milliseconds=valid_ms),

            clset = msg.get(MsgKeys.HELLO_CLSET, [])
            for cldef in clset:
                cltype = cldef.get(ClKeys.CL_TYPE)
                if cltype == ClType.UDPCL:
                    import re
                    addr_list = cldef.get(ClKeys.ADDR, [])
                    route = TxRouteItem(
                        eid_pattern=re.compile(r''),
                        next_nodeid=node_id,
                        cl_type='udpcl',
                        raw_config=dict(
                            address=str(ipaddress.ip_address(addr_list[0])),
                            port=cldef.get(ClKeys.PORT, 4556),
                        ),
                    )

                LOGGER.info('CL %s to route %s', cldef, route)
                if route:
                    neighbor.tx_routes.append(route)

            peerset = msg.get(MsgKeys.HELLO_PEERSET, [])
            for peer in peerset:
                (peer_nodeid, peer_link_status) = peer
                if (
                    self._config.node_id == peer_nodeid
                    and peer_link_status in (LinkStatus.HEARD, LinkStatus.SYMMETRIC)
                ):
                    neighbor.link_status = LinkStatus.SYMMETRIC

            LOGGER.info('HELLO from: %s', neighbor)

        else:
            LOGGER.warning('Ignoring unknown NMP message type %s', msg_type)

        return True

    def _tx_route(self, ctr):
        ''' Use discovered routes.
        '''
        eid = ctr.bundle.primary.destination
        if eid in self._one_hop:
            ctr.route = self._one_hop[eid].tx_routes[0]

        ctr.record_action('deliver')

    def _send_msg(self, msg, remote_addr, local_addr):
        ''' Send an NMP message

        :param msg: The message content.
        :param local_addr: The address to send from.
        '''
        LOGGER.info('Message TX: %s', encode_diagnostic(msg))

        ctr = BundleContainer()
        ctr.bundle.primary = PrimaryBlock(
            bundle_flags=(
                PrimaryBlock.Flag.NO_FRAGMENT
                | PrimaryBlock.Flag.REQ_DELIVERY_REPORT
            ),
            destination='dtn:~neighbor',
            crc_type=AbstractBlock.CrcType.CRC32,
        )
        ctr.bundle.blocks = [
            CanonicalBlock(
                type_code=1,
                block_num=1,
                crc_type=AbstractBlock.CrcType.CRC32,
                btsd=cbor2.dumps(msg),
            ),
        ]
        # Force the route
        ctr.route = TxRouteItem(
            eid_pattern=None,
            next_nodeid=ctr.bundle.primary.destination,
            cl_type='udpcl',
            raw_config=dict(
                address=remote_addr,
                port=4556,
                local_addr=local_addr,
            ),
        )

        self._agent.send_bundle(ctr)

    def _now(self):
        ''' Get current time
        '''
        return datetime.datetime.now(datetime.timezone.utc)

    def _timer_hello(self):
        ''' Periodic timer to emit HELLO.
        '''
        if self._last_hello is None or self._now() - self._last_hello > self._hello_min_intvl:
            self.hello()
        return True

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='')
    def hello(self):
        ''' Send a NHDP HELLO message.

        '''
        # Only use name if resolves to external address
        own_name = socket.gethostname()
        own_addr = ipaddress.ip_address(socket.gethostbyname(own_name))
        if own_addr.is_loopback or own_addr.is_link_local:
            own_name = None

        for (_if_name, items) in psutil.net_if_addrs().items():
            name_objs = []
            addr_objs = []
            local_ipv4 = None
            local_ipv6 = None
            for item in items:
                if item.family not in (socket.AF_INET, socket.AF_INET6):
                    continue

                if item.family == socket.AF_INET6 and '%' in item.address:
                    addr = item.address.split('%')[0]
                else:
                    addr = item.address
                addr = ipaddress.ip_address(addr)
                if addr.is_loopback or addr.is_link_local:
                    continue

                if not local_ipv4 and item.family == socket.AF_INET:
                    local_ipv4 = str(addr)
                if not local_ipv6 and item.family == socket.AF_INET6:
                    local_ipv6 = str(addr)

                if addr == own_addr:
                    name_objs.append(own_name)
                addr_objs.append(
                    addr.packed
                )

            # nothing to offer on this interface
            if not addr_objs:
                continue

            peer_objs = []
            for item in self._one_hop.values():
                peer_objs.append([
                    item.node_id,
                    item.link_status,
                ])

            msg = {
                MsgKeys.MSG_TYPE: MsgType.HELLO,
                MsgKeys.HELLO_VALIDITY_TIME: 123,
                MsgKeys.HELLO_INTERVAL_TIME: 456,
                MsgKeys.HELLO_CLSET: [
                    {
                        ClKeys.CL_TYPE: ClType.UDPCL,
                        ClKeys.DNSNAME: name_objs,
                        ClKeys.ADDR: addr_objs,
                    },
                ],
                MsgKeys.HELLO_PEERSET: peer_objs,
            }

            if local_ipv4:
                self._send_msg(msg, '224.0.0.1', local_ipv4)
            if local_ipv6:
                self._send_msg(msg, 'FF02::1', local_ipv6)

        self._last_hello = self._now()
