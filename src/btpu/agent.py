'''
Implementation of a symmetric BTP-UoE agent.
'''
import copy
from dataclasses import dataclass, astuple, field
from datetime import datetime, timezone
import enum
from typing import (
    Callable, ClassVar, Dict, Optional, BinaryIO, List, Tuple, Iterable
)
import logging
import macaddress
import os
import psutil
from io import BytesIO
import socket
import struct
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.arch.linux import (
    SOL_PACKET,
    PACKET_AUXDATA,
    PACKET_ADD_MEMBERSHIP,
    PACKET_MR_MULTICAST,
)
import portion
import dbus.service
from gi.repository import GLib as glib

from btpu.config import Config, ListenConfig, PollConfig
from btpu.messages import (
    MessageSet, MessageHead, BundlePdu, TransferSeg, TransferEnd, HintHead
)

LOGGER = logging.getLogger(__name__)

RX_XFER_TIMEOUT_MS = 1000


@enum.unique
class ExtensionKey(enum.IntEnum):
    ''' Extension map keys.
    '''
    TRANSFER = 0x02
    SENDER_LISTEN = 0x03
    SENDER_NODEID = 0x04
    STARTTLS = 0x05
    PEER_PROBE = 0x06
    PEER_CONFIRM = 0x07
    ECN_COUNTS = 0x08


def address_from_if(ifname: str) -> macaddress.HWAddress:
    try:
        addrs = psutil.net_if_addrs()[ifname]
        for item in addrs:
            if item.family != psutil.AF_LINK:
                continue
            LOGGER.debug('Got interface address for "%s" as %s', ifname, item.address)
            # first address wins
            return macaddress.EUI48(item.address)

    except Exception as err:
        LOGGER.error('Failed to find interface "%s" err: %s', ifname, err)
        raise


@dataclass
class BundleItem(object):
    ''' State for RX and TX full bundles.
    '''

    # The remote address
    address: str
    # Binary file to store in
    file: BinaryIO

    local_if: Optional[int] = None
    ''' Optional local interface index '''
    # Optional source address
    local_address: Optional[str] = None
    # The unique transfer ID number.
    transfer_id: Optional[int] = None
    # Size of the bundle data
    total_length: Optional[int] = None

    sock_opts: List[Tuple] = field(default_factory=list)
    ''' Additional three-tuple of :py:meth:`socket.setsockopt` parameters '''


class IntInterval(portion.AbstractDiscreteInterval):
    ''' An integer-domain interval class '''
    _step = 1


apiIntInterval = portion.create_api(IntInterval)
''' Utility functions for :py:cls:`IntInterval` '''


@dataclass
class RxTransfer(object):
    ''' State for segmented transfers.
    '''

    got_end: Optional[int] = None
    ''' The last index once the end has been received '''
    got_idx: IntInterval = apiIntInterval.empty()
    ''' Range of segment index present '''
    data: Dict[int, bytes] = field(default_factory=dict)
    ''' Accumulated byte strings by index '''

    timeout_id: Optional[int] = None
    ''' glib timer ID to time out this transfer.
    It gets reset each time a new segment is received.
    '''


class VirtualChannel:
    ''' Base class for channel bookkeeping '''

    @property
    def key(self):
        raise NotImplementedError

    def make_local_socket(self):
        ''' Get a socket based on local requirements.
        :return: A socket object.
        '''
        raise NotImplementedError

    def get_peer_addr(self):
        ''' Get a peer address suitable for use with :py:meth:`socket.sendto`.
        :return: An address tuple.
        '''
        raise NotImplementedError


@dataclass
class EthernetChannel(VirtualChannel):
    ''' Bookkeep parameters of a BTPUoE channel
    which is address for each side plus optional VLAN tag.
    '''

    ETHERTYPE: ClassVar[int] = 0x88b5
    ''' Ethertype for BTPU '''

    local_if: Optional[str] = None
    ''' Local interface index '''
    peer_address: Optional[macaddress.HWAddress] = None
    ''' Remote side address '''
    local_address: Optional[macaddress.HWAddress] = None
    ''' Local side address '''
    vlan_tag: Optional[int] = None
    ''' VLAN tag '''

    @property
    def key(self):
        return astuple(self)

    def make_local_socket(self):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, self.ETHERTYPE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self.local_address and self.local_if != '':
            # specific interface for AF_PACKET raw mode
            sockaddr = (
                self.local_if,
                self.ETHERTYPE,
                0,  # pkttype
                0,  # hatype
                bytes(self.local_address),
            )
            LOGGER.debug('make_local_socket bind to %s', sockaddr)
            sock.bind(sockaddr)

        return sock

    def get_peer_addr(self):
        return (
            self.local_if,
            self.ETHERTYPE,
            0,  # pkttype
            0,  # hatype
            bytes(self.peer_address)
        )


@dataclass
class EthernetSender:
    ''' Functional class to send a UDP datagram with socket options.
    '''
    sock: socket.socket
    ''' Socket to send on. '''
    src: macaddress.HWAddress
    ''' Own source address for the interface. '''
    dst: macaddress.HWAddress
    ''' Destination address. '''

    def __call__(self, data: bytes) -> None:
        ''' Send it '''
        LOGGER.debug('Sending message size %d from %s to %s', len(data), self.src, self.dst)
        eth_fields = dict(src=bytes(self.src), dst=bytes(self.dst), type=EthernetChannel.ETHERTYPE)
        frame = bytes(Ether(**eth_fields) / Raw(data))
        self.sock.send(frame)


class Agent(dbus.service.Object):
    ''' Overall agent behavior.

    :param config: The agent configuration object.
    :type config: :py:class:`Config`
    :param bus_kwargs: Arguments to :py:class:`dbus.service.Object` constructor.
        If not provided the default dbus configuration is used.
    :type bus_kwargs: dict or None
    '''

    DBUS_IFACE = 'org.ietf.dtn.btpu.Agent'

    def __init__(self, config: Config, bus_kwargs=None):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._config = config
        self._on_stop: Optional[Callable[[], None]] = None

        self._bindsocks: Dict[Tuple, socket.socket] = {}
        # Map from RX socket to glib io-watch ID
        self._recv_wait: Dict[socket.socket, int] = {}
        # Existing sockets, map from `VirtualChannel.key` to `socket.socket`
        self._plain_sock: Dict[Tuple, socket.socket] = {}

        self._tx_id: int = 0
        self._tx_queue: List[BundleItem] = []
        self._rx_progres: Dict[Tuple[Tuple, int], RxTransfer] = {}
        self._rx_id: int = 0
        self._rx_queue: Dict[int, BundleItem] = {}

        if bus_kwargs is None:
            bus_kwargs = dict(
                conn=config.bus_conn,
                object_path='/org/ietf/dtn/btpu/Agent'
            )
        dbus.service.Object.__init__(self, **bus_kwargs)

        if self._config.bus_service:
            self._bus_serv = dbus.service.BusName(
                bus=self._config.bus_conn,
                name=self._config.bus_service,
                do_not_queue=True
            )
            self.__logger.info('Registered as "%s"', self._bus_serv.get_name())

        for item in self._config.init_listen:
            self.listen(item.ifname, item.opts)
        for item in self._config.polling:
            self.polling_start(item)

    def is_transfer_idle(self):
        ''' Determine if the agent is idle.

        :return: True if there are no data being processed RX or TX side.
        '''
        return len(self._rx_queue) == 0 and len(self._tx_queue) == 0

    def set_on_stop(self, func: Callable[[], None]):
        ''' Set a callback to be run when this agent is stopped.

        :param func: The callback, which takes no arguments.
        '''
        self._on_stop = func

    @dbus.service.method(DBUS_IFACE, in_signature='')
    def stop(self):
        ''' Immediately stop the agent and disconnect any sessions. '''
        self.__logger.info('Stopping agent')
        for spec in tuple(self._bindsocks.keys()):
            conv = EthernetChannel(*spec)
            try:
                self._listen_stop(conv)
            except:
                pass

        if self._on_stop:
            self._on_stop()

    def exec_loop(self):
        ''' Run this agent in an event loop.
        The on_stop callback is replaced to quit the event loop.
        '''
        eloop = glib.MainLoop()
        self.set_on_stop(eloop.quit)
        self.__logger.info('Starting event loop')
        try:
            eloop.run()
        except KeyboardInterrupt:
            self.stop()

    @dbus.service.method(DBUS_IFACE, in_signature='sa{sv}')
    def listen(self, ifname, opts=None):
        ''' Begin listening for incoming transfers and defer handling
        connections to `glib` event loop.
        '''
        if opts is None:
            opts = {}

        macaddr = address_from_if(ifname)
        conv = EthernetChannel(
            local_if=ifname,
            local_address=macaddr
        )
        if conv.key in self._bindsocks:
            raise dbus.DBusException('Already listening')

        sock = conv.make_local_socket()
        self.__logger.info('Listening on %s addr %s', conv.local_if, conv.local_address)

        # always receive src MAC and VLAN TPID data
        sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)

        multicast_member = opts.get('multicast_member', [])
        for item in multicast_member:
            addr = macaddress.EUI48(item['addr'])
            iface_ix = socket.if_nametoindex(conv.local_if) if conv.local_if else 0
            self.__logger.info('Listening for multicast %s on %s (%s)', addr, conv.local_if, iface_ix)
            mreq = (
                struct.pack("@IHH8s", iface_ix, PACKET_MR_MULTICAST, 6, bytes(addr))
            )
            sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)

        self._bindsocks[conv.key] = sock
        self._recv_wait[sock] = glib.io_add_watch(sock, glib.IO_IN, self._sock_recvfrom)

    @dbus.service.method(DBUS_IFACE, in_signature='s')
    def listen_stop(self, ifname):
        ''' Stop listening for transfers on an existing port binding.
        '''
        addrobj = AddressObject(ifname)
        conv = EthernetChannel(
            local_if=addrobj.ifname,
            local_address=addrobj.macaddr
        )
        self._listen_stop(conv)

    def _listen_stop(self, conv):
        if conv.key not in self._bindsocks:
            raise dbus.DBusException('Not listening')

        sock = self._bindsocks.pop(conv.key)
        self.__logger.info('Un-listening on %s %s', conv.local_if, conv.local_address)
        if sock in self._recv_wait:
            glib.source_remove(self._recv_wait.pop(sock))
        sock.close()

    def _sock_recvfrom(self, sock: socket.socket, *_args, **_kwargs) -> bool:
        ''' Callback to handle incoming frames.

        :return: True to continue listening.
        '''
        datalen = 64 * 1024

        data, fromaddr = sock.recvfrom(datalen)
        pkttype = fromaddr[2]
        if pkttype in {socket.PACKET_OTHERHOST, socket.PACKET_OUTGOING}:
            # not interested
            return True

        localaddr = sock.getsockname()
        local_if = localaddr[0]
        local_mac = localaddr[4]

        # raw frame with decoded payload
        frame = Ether(data)

        src_addr = macaddress.EUI48(frame.getfieldval('src'))
        dst_addr = macaddress.EUI48(frame.getfieldval('dst'))
        # if src_addr.macaddr == local_mac:
        #     return True
        LOGGER.info('Got frame on %s from %s\n%s', localaddr, fromaddr, frame.show(True))

        conv = EthernetChannel(
            local_if=local_if,
            peer_address=src_addr,
            local_address=dst_addr,
        )
        self.__logger.info('Received %d octets via plain on %s',
                           len(frame.payload), conv)
        self._plain_sock[conv.key] = sock
        self._recv_msg(sock, frame.payload.load, conv)
        return True

    def _recv_msg(self, _sock, data: bytes, conv: VirtualChannel):
        timestamp = datetime.now(timezone.utc)

        try:
            pkt = MessageSet(data)
            self.__logger.debug('Decoded %d messages', len(pkt.msgs))
        except Exception as err:
            self.__logger.error('Failed decoding messages with: %s', err)
            return

        for msg in pkt.msgs:
            if isinstance(msg.payload, BundlePdu):
                self.__logger.debug('Received full bundle size %d', len(msg.payload.load))
                self._add_rx_item(
                    BundleItem(
                        local_if=conv.local_if,
                        address=str(conv.peer_address),
                        total_length=len(msg.payload.load),
                        file=BytesIO(msg.payload.load)
                    )
                )

            elif isinstance(msg.payload, (TransferSeg, TransferEnd)):
                self.__logger.debug('Received transfer-seg xfer_num=%d, seg_idx=%d, size %d',
                                    msg.payload.xfer_num, msg.payload.seg_idx, len(msg.payload.payload.load))
                key = (conv.key, msg.payload.xfer_num)
                xfer: RxTransfer = self._rx_progres.setdefault(key, RxTransfer())

                if msg.payload.seg_idx not in xfer.got_idx:
                    # new segment
                    if isinstance(msg.payload, TransferEnd):
                        xfer.got_end = msg.payload.seg_idx

                    xfer.got_idx |= apiIntInterval.singleton(msg.payload.seg_idx)
                    xfer.data[msg.payload.seg_idx] = msg.payload.payload.load
                    self.__logger.debug('Current transfer state %s of %s', xfer.got_idx, xfer.got_end)
                    glib.timeout_add(RX_XFER_TIMEOUT_MS, self._rx_progress_cancel, key)

                    if xfer.got_end:
                        # the full range is known at least
                        full_idx = apiIntInterval.closed(0, xfer.got_end)

                        if xfer.got_idx == full_idx:
                            self.__logger.debug('Received all %d indices', xfer.got_end + 1)
                            fulldata = bytes()
                            for idx in portion.iterate(full_idx, step=1):
                                fulldata += xfer.data.pop(idx)

                            self._add_rx_item(
                                BundleItem(
                                    local_if=conv.local_if,
                                    address=str(conv.peer_address),
                                    total_length=len(fulldata),
                                    file=BytesIO(fulldata)
                                )
                            )
                            self._rx_progress_cancel(key)
            else:
                self.__logger.error('Unhandled message: %s', msg.show(True))

    def _rx_progress_cancel(self, key):
        # TODO keep this around for a while while the window is still open
        del self._rx_progres[key]

    def _add_rx_item(self, item: BundleItem):
        ''' Add a recevied bundle.
        '''
        item.transfer_id = copy.copy(self._rx_id)
        self._rx_id += 1

        metadata = {
            'address': item.address,
        }
        if item.local_address:
            metadata['local_address'] = item.local_address

        self._rx_queue[item.transfer_id] = item
        self.recv_bundle_finished(str(item.transfer_id), item.total_length, metadata)

    @dbus.service.signal(DBUS_IFACE, signature='sta{sv}')
    def recv_bundle_finished(self, bid: str, length: int, metadata: Dict):
        ''' Indicate that a bundle has been received.
        '''

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='as')
    def recv_bundle_get_queue(self):
        return dbus.Array([str(bid) for bid in self._rx_queue.keys()])

    @dbus.service.method(DBUS_IFACE, in_signature='s', out_signature='ay')
    def recv_bundle_pop_data(self, bid):
        bid = int(bid)
        item = self._rx_queue.pop(bid)
        item.file.seek(0)
        return item.file.read()

    @dbus.service.method(DBUS_IFACE, in_signature='ss', out_signature='')
    def recv_bundle_pop_file(self, bid, filepath):
        bid = int(bid)
        item = self._rx_queue.pop(bid)
        item.file.seek(0)

        import shutil
        out_file = open(filepath, 'wb')
        shutil.copyfileobj(item.file, out_file)

    def send_bundle_fileobj(self, file, tx_params):
        ''' Send bundle from a file-like object.

        :param file: The file to send.
        :type file: file-like
        :param tx_params: Additional transfer parameters.
        :return: The new transfer ID.
        :rtype: int
        '''
        item = BundleItem(
            address=str(tx_params['address']),
            local_if=(str(tx_params['local_if']) if 'local_if' in tx_params else None),
            local_address=(str(tx_params['local_address']) if 'local_address' in tx_params else None),
            file=file
        )
        return str(self._add_tx_item(item))

    @dbus.service.method(DBUS_IFACE, in_signature='aya{sv}', out_signature='s')
    def send_bundle_data(self, data, tx_params):
        ''' Send bundle data directly.
        '''
        # byte array to bytes
        data = b''.join([bytes([val]) for val in data])
        tx_params = dict(tx_params)
        self.__logger.debug('send_bundle_data data len %d, tx_params %s', len(data), tx_params)
        return self.send_bundle_fileobj(BytesIO(data), tx_params)

    def _add_tx_item(self, item, is_transfer: bool = True):
        if is_transfer and item.transfer_id is None:
            item.transfer_id = copy.copy(self._tx_id)
            self._tx_id += 1

        item.file.seek(0, os.SEEK_END)
        item.total_length = item.file.tell()
        item.file.seek(0)

        self._tx_queue.append(item)
        self._process_tx_queue_trigger()
        return item.transfer_id

    def _process_tx_queue_trigger(self):
        if self._tx_queue:
            glib.idle_add(self._process_tx_queue)

    def _send_transfer(self, item) -> Iterable[bytes]:
        ''' An iterator for datagrams, segmenting as necessary.

        :param item: The item to send.
        :type item: :py:class:`BundleItem`
        '''
        mtu = self._config.mtu_default
        data = item.file.read()
        total_len = len(data)

        self.__logger.info('Transfer %d size %d relative to MTU %s',
                           item.transfer_id, total_len, mtu)
        if mtu is None or total_len < (mtu - 4):
            # no segmentation
            msg = MessageHead()/BundlePdu(data)
            yield msg
        else:
            # common heading
            msg_head = MessageHead(
                hints=[
                    HintHead(hint_type=0)/Raw(total_len.to_bytes(4, 'big'))
                ]
            )

            # Size left for transfer data
            remain_size = mtu - len(msg_head) - 8

            seg_idx = 0
            seg_offset = 0
            while seg_offset < total_len:
                seg_data = data[seg_offset:(seg_offset + remain_size)]
                seg_offset += remain_size

                # common fields
                fields = dict(xfer_num=item.transfer_id, seg_idx=seg_idx)

                if seg_offset < total_len:
                    # more remaining
                    msg = msg_head/TransferSeg(**fields)/Raw(seg_data)
                else:
                    msg = msg_head/TransferEnd(**fields)/Raw(seg_data)
                seg_idx += 1

                yield bytes(msg)

    def _process_tx_queue(self):
        ''' Perform the next TX bundle if possible.

        :return: True to continue processing at a later time.
        :rtype: bool
        '''
        if not self._tx_queue:
            return
        self.__logger.debug('Processing queue of %d items',
                            len(self._tx_queue))

        # work from the head of the list
        item: BundleItem = self._tx_queue.pop(0)

        if item.transfer_id is not None:
            self.send_bundle_started(
                str(item.transfer_id),
                item.total_length
            )

        peer_addrobj = macaddress.EUI48(item.address)
        local_addrobj = address_from_if(item.local_if)
        conv = EthernetChannel(
            local_if=item.local_if,
            peer_address=peer_addrobj,
            local_address=local_addrobj,
        )
        self.__logger.info('Sending %d octets on %s', item.total_length, conv)

        sock = self._plain_sock.get(conv.key)
        if sock is None:
            self.__logger.debug('New conversation seen %s', conv)
            sock = conv.make_local_socket()
            self._plain_sock[conv.key] = sock

        # Listen for any return-path regardless
        if sock not in self._recv_wait:
            self._recv_wait[sock] = glib.io_add_watch(sock, glib.IO_IN, self._sock_recvfrom)

        sender = EthernetSender(
            sock=sock,
            src=conv.local_address,
            dst=conv.peer_address,
        )

        # VLAN marking
        # FIXME TBD

        msg_iter = self._send_transfer(item)
        # FIXME synchronous
        for data in msg_iter:
            sender(data)

        return bool(self._tx_queue)

    @dbus.service.signal(DBUS_IFACE, signature='st')
    def send_bundle_started(self, bid, length):
        pass

    @dbus.service.signal(DBUS_IFACE, signature='sts')
    def send_bundle_finished(self, bid, length, result):
        pass
