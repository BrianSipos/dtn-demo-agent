''' Application layer adaptors.
'''
import cbor2
from dataclasses import dataclass, field, fields
import datetime
import dbus.service
import enum
from gi.repository import GLib as glib
import io
import ipaddress
import logging
import psutil
import re
import socket
import traceback
from typing import List

from scapy_cbor.util import encode_diagnostic
from bp.config import Config, TxRouteItem
from bp.encoding import (
    AbstractBlock, PrimaryBlock, CanonicalBlock, HopCountBlock,
    BlockIntegrityBlock
)
from bp.util import BundleContainer, ChainStep
from bp.app.base import app, AbstractApplication
from .bpsec import load_pem_key, load_pem_chain, encode_der_cert, BPSEC_COSE_CONTEXT_ID

LOGGER = logging.getLogger(__name__)

NEIGHBOR_EID = 'ipn:100.1'


class MsgKeys(enum.IntEnum):
    MSG_TYPE = 0
    REFERENCE_TIME = 2
    VALIDITY_DURATION = 3
    REPITITION_INTERVAL = 4


@enum.unique
class MsgType(enum.IntEnum):
    SOLICIT = 1
    IDENTITY_ADVERT = 2
    CL_ADVERT = 3
    RESOURCE_ADVERT = 4
    LT_ADVERT = 5
    ROUTER_ADVERT = 6
    ENDPOINT_ADVERT = 7


@enum.unique
class IdentityAdvertKeys(enum.IntEnum):
    X5BAG = -1


@enum.unique
class ClAdvertKeys(enum.IntEnum):
    CLSET = -1


@enum.unique
class LtAdvertKeys(enum.IntEnum):
    PEERSET = -1


class ClKeys(enum.IntEnum):
    CL_TYPE = 0
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

    # : The reassembled bundle ident
    node_id: str = ''
    # : Time at which this data becomes invalid
    valid_until = None
    # : Latest inferred status
    link_status: LinkStatus = None
    # : List of TX routes reported for this node
    tx_routes: List[TxRouteItem] = field(default_factory=list)


@app('nmp')
class Nmp(AbstractApplication):
    ''' Neighbor messaging protocol.
    '''

    # : Interface name
    DBUS_IFACE = 'org.ietf.dtn.bp.nmp'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._sign_key = None
        self._sign_chain = []
        self._encr_chain = []

        self._config = None
        self._nmp_eid = None
        self._last_hello = None
        self._hello_min_intvl = None
        self._one_hop = {}
        self._ka_resp = {}

    def load_config(self, config:Config):
        super().load_config(config)
        self._config = config

        if config.sign_key_file:
            with open(config.sign_key_file, 'rb') as infile:
                self._sign_key = load_pem_key(infile)
        if config.sign_cert_file:
            with open(config.sign_cert_file, 'rb') as infile:
                self._sign_chain = load_pem_chain(infile)
        if config.encr_cert_file:
            with open(config.encr_cert_file, 'rb') as infile:
                self._encr_chain = load_pem_chain(infile)

        nmp_config = self._config.apps.get(self._app_name, {})
        LOGGER.debug('nmp_config %s', nmp_config)

        self._nmp_eid = nmp_config.get('endpoint')

        self._hello_min_intvl = datetime.timedelta(
            seconds=nmp_config.get('hello_min_intvl', 1)
        )
        self._hello_nom_intvl = datetime.timedelta(
            seconds=nmp_config.get('hello_nom_intvl', 10)
        )

        if nmp_config.get('enable', False):
            hello_intvl_ms = self._hello_nom_intvl // datetime.timedelta(milliseconds=1)
            LOGGER.info('Sending HELLO at interval %d ms', hello_intvl_ms)
            glib.timeout_add(hello_intvl_ms, self._timer_hello)
            # glib.idle_add(self._timer_hello)

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
        if eid in (self._nmp_eid, NEIGHBOR_EID):
            ctr.record_action('deliver')

    def _recv_bundle(self, ctr:BundleContainer) -> bool:
        if self._recv_for(ctr, NEIGHBOR_EID):
            return self._recv_group(ctr)
        elif self._recv_for(ctr, self._nmp_eid):
            return self._recv_own(ctr)
        else:
            return False

    def _recv_group(self, ctr:BundleContainer) -> bool:
        adu = io.BytesIO(ctr.block_num(1).getfieldval('btsd'))
        dec = cbor2.CBORDecoder(adu)

        # message-independent bookkeeping
        if True:
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
            LOGGER.info('HELLO from: %s', neighbor)

        while adu.tell() < len(adu.getvalue()):
            msg = dec.decode_from_bytes(dec.decode())
            LOGGER.info('Message RX: %s', encode_diagnostic(msg))

            msg_type = msg[MsgKeys.MSG_TYPE]
            if msg_type == MsgType.IDENTITY_ADVERT:
                x5bag = msg.get(IdentityAdvertKeys.X5BAG)
                if x5bag:
                    cosectx = self._agent._app['bpsec'].get_context(BPSEC_COSE_CONTEXT_ID)
                    LOGGER.info('Adding peer x5bag with %d certificates', len(x5bag))
                    # no chain validation at this point
                    for data in x5bag:
                        cosectx.cert_store.add_untrusted_cert(data)

                valid_ms = msg.get(MsgKeys.VALIDITY_DURATION)
                if valid_ms is not None and pri_blk.create_ts.dtntime:
                    neighbor.valid_until = pri_blk.create_ts.dtntime + datetime.timedelta(milliseconds=valid_ms),

            elif msg_type == MsgType.CL_ADVERT:
                clset = msg.get(ClAdvertKeys.CLSET, [])
                for cldef in clset:
                    cltype = cldef.get(ClKeys.CL_TYPE)
                    if cltype == ClType.UDPCL:
                        addr_list = cldef.get(ClKeys.ADDR, [])
                        if not addr_list:
                            continue
                        route = TxRouteItem(
                            eid_pattern=re.compile(r''),
                            next_nodeid=node_id,
                            cl_type='udpcl',
                            raw_config=dict(
                                address=str(ipaddress.ip_address(addr_list[0])),
                                port=cldef.get(ClKeys.PORT, 4556),
                            ),
                        )
                    elif cltype == ClType.TCPCL:
                        addr_list = cldef.get(ClKeys.ADDR, [])
                        if not addr_list:
                            continue
                        route = TxRouteItem(
                            eid_pattern=re.compile(r''),
                            next_nodeid=node_id,
                            cl_type='tcpcl',
                            raw_config=dict(
                                address=str(ipaddress.ip_address(addr_list[0])),
                                port=cldef.get(ClKeys.PORT, 4556),
                            ),
                        )

                    LOGGER.info('CL %s to route %s', cldef, route)
                    if route and route not in neighbor.tx_routes:
                        neighbor.tx_routes.append(route)

            elif msg_type == MsgType.LT_ADVERT:
                peerset = msg.get(LtAdvertKeys.PEERSET, [])
                for peer in peerset:
                    (peer_nodeid, peer_link_status) = peer
                    if (
                        self._config.node_id == peer_nodeid
                        and peer_link_status in (LinkStatus.HEARD, LinkStatus.SYMMETRIC)
                    ):
                        neighbor.link_status = LinkStatus.SYMMETRIC

            else:
                LOGGER.warning('Ignoring unknown NMP message type %s', msg_type)

        return True

    def _recv_own(self, ctr:BundleContainer) -> bool:
        return self._recv_group(ctr)

    def _tx_route(self, ctr):
        ''' Use discovered routes.
        '''
        eid = ctr.bundle.primary.destination
        if eid in self._one_hop:
            ctr.route = self._one_hop[eid].tx_routes[0]
            LOGGER.debug('Setting one-hop neighbor route to %s as %s', eid, ctr.route)

    def _gen_bundle(self, adu:bytes, dest):
        LOGGER.info('Message TX: %s', encode_diagnostic(adu))

        ctr = BundleContainer()
        ctr.bundle.primary = PrimaryBlock(
            bundle_flags=(
                PrimaryBlock.Flag.NO_FRAGMENT
            ),
            source=self._nmp_eid,
            destination=dest,
            crc_type=AbstractBlock.CrcType.CRC32,
        )
        ctr.bundle.blocks = [
            CanonicalBlock(
                block_num=2,
                crc_type=AbstractBlock.CrcType.CRC32,
            ) / HopCountBlock(
                limit=1,
                count=0
            ),
            CanonicalBlock(
                type_code=1,
                block_num=1,
                crc_type=AbstractBlock.CrcType.CRC32,
                btsd=adu,
            ),
        ]
        return ctr

    def _send_msg(self, ctr, address, local_address, local_if):
        ''' Send an NMP message

        :param ctr: The message container.
        :param address: The remote address to send to.
        :param local_address: The address to send from.
        '''

        # Force the route
        ctr.route = TxRouteItem(
            eid_pattern=None,
            next_nodeid=ctr.bundle.primary.destination,
            cl_type='udpcl',
            raw_config=dict(
                address=address,
                port=4556,
                local_address=local_address,
                local_if=local_if,
            ),
        )

        try:
            self._agent.send_bundle(ctr)
        except Exception:
            LOGGER.error('Failed to send\n%s', traceback.format_exc())

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
        ''' Send a SAND HELLO message.

        '''
        # Only use name if resolves to external address
        own_name = socket.gethostname()
        own_addr = ipaddress.ip_address(socket.gethostbyname(own_name))
        if own_addr.is_loopback or own_addr.is_link_local:
            own_name = None

        # Each interface gets its own message
        for (if_name, items) in psutil.net_if_addrs().items():
            name_objs = []
            addr_objs = []
            local_if = None
            local_ipv4 = None
            local_ipv6 = None
            for item in items:
                if item.family not in {socket.AF_INET, socket.AF_INET6}:
                    continue

                if item.family == socket.AF_INET6 and '%' in item.address:
                    addr = item.address.split('%')[0]
                else:
                    addr = item.address
                addr = ipaddress.ip_address(addr)
                if addr.is_loopback:
                    continue

                local_if = socket.if_nametoindex(if_name)
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

            LOGGER.info('Sending hello on %s with %s and %s', if_name, local_ipv4, local_ipv6)

            peer_objs = []
            for item in self._one_hop.values():
                peer_objs.append([
                    item.node_id,
                    item.link_status,
                ])

            cert_bag = set()
            for cert in self._sign_chain + self._encr_chain:
                cert_bag.add(encode_der_cert(cert))

            intvl_ms = self._hello_nom_intvl // datetime.timedelta(milliseconds=1)
            msgset = [
                {
                    MsgKeys.MSG_TYPE: MsgType.IDENTITY_ADVERT,
                    MsgKeys.VALIDITY_DURATION: 2 * intvl_ms,
                    MsgKeys.REPITITION_INTERVAL: intvl_ms,
                    IdentityAdvertKeys.X5BAG: list(cert_bag),
                },
                {
                    MsgKeys.MSG_TYPE: MsgType.CL_ADVERT,
                    MsgKeys.VALIDITY_DURATION: 2 * intvl_ms,
                    MsgKeys.REPITITION_INTERVAL: intvl_ms,
                    ClAdvertKeys.CLSET: [
                        {
                            ClKeys.CL_TYPE: ClType.UDPCL,
                            ClKeys.DNSNAME: name_objs,
                            ClKeys.ADDR: addr_objs,
                        },
                    ],
                }
            ]
            # adu is sequence of bstrs of message maps
            adu = io.BytesIO()
            enc = cbor2.CBOREncoder(adu)
            for msg in msgset:
                enc.encode(enc.encode_to_bytes(msg))

            ctr = self._gen_bundle(adu.getvalue(), NEIGHBOR_EID)
            if local_ipv4:
                self._send_msg(ctr, '224.0.1.186', local_ipv4, local_if)
            if local_ipv6:
                ctr.sender = None
                for blk in ctr.block_type(BlockIntegrityBlock):
                    ctr.remove_block(blk)

                self._send_msg(ctr, 'FF05::1:5', local_ipv6, local_if)

        self._last_hello = self._now()
