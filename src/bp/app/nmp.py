''' Application layer adaptors.
'''
import cbor2
import dbus.service
import enum
import ipaddress
import logging
import psutil
import socket

from scapy_cbor.util import encode_diagnostic
from bp.encoding import (
    Bundle, AbstractBlock, PrimaryBlock, CanonicalBlock,
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


@app('/org/ietf/dtn/bp/nmp')
class Nmp(AbstractApplication):
    ''' Neighbor messaging protocol.
    '''

    #: Interface name
    DBUS_IFACE = 'org.ietf.dtn.bp.nmp'

    def add_chains(self, rx_chain, tx_chain):
        rx_chain.append(ChainStep(
            order=-1,
            name='NMP handle',
            action=self._recv_nmp
        ))

    def _recv_nmp(self, ctr):
        eid = ctr.bundle.primary.destination
        if eid != 'dtn:~neighbor':
            return

        ctr.record_action('deliver')
        LOGGER.info('Received %s', cbor2.loads(ctr.block_num(1).getfieldval('btsd')))

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='')
    def hello(self):
        ''' Send a NHDP HELLO message.

        '''
        dest = 'dtn:~neighbor'

        addr_objs = []
        for (_name, items) in psutil.net_if_addrs().items():
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

                addr_objs.append(
                    addr.packed
                )

        msg = {
            MsgKeys.MSG_TYPE: MsgType.HELLO,
            MsgKeys.HELLO_VALIDITY_TIME: 123,
            MsgKeys.HELLO_INTERVAL_TIME: 456,
            MsgKeys.HELLO_CLSET: [
                {
                    ClKeys.CL_TYPE: ClType.UDPCL,
                    ClKeys.DNSNAME: [
                        socket.gethostname(),
                    ],
                    ClKeys.ADDR: addr_objs,
                },
            ],
        }
        LOGGER.info('HELLO tx: %s', encode_diagnostic(msg))

        ctr = BundleContainer()
        ctr.bundle.primary = PrimaryBlock(
            bundle_flags=(
                PrimaryBlock.Flag.NO_FRAGMENT
                | PrimaryBlock.Flag.REQ_RECEPTION_REPORT
                | PrimaryBlock.Flag.REQ_DELIVERY_REPORT
            ),
            destination=dest,
            source=self._agent._config.node_id,
            report_to=self._agent._config.node_id,
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

        self._agent.send_bundle(ctr)

    def accept(self, ctr):
        dest_eid = str(ctr.bundle.primary.destination)
        if dest_eid != 'dtn:~neighbor':
            return False

        payload = ctr.block_num(1).btsd
        msg = cbor2.loads(payload)
        LOGGER.info('HELLO rx: %s', encode_diagnostic(msg))
        return True
