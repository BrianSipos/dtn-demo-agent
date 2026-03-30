'''
Implementation of a symmetric LTPCL entity.
'''
import copy
from dataclasses import dataclass, astuple, field
from datetime import datetime, timezone
from typing import Optional, BinaryIO, Dict, List, Tuple
import ipaddress
import logging
import os
from io import BytesIO, BufferedReader
import random
import socket
import struct
import cbor2
import portion
import dbus.service
from gi.repository import GLib as glib
from scapy.contrib import ltp
from ltpcl.config import Config


LOGGER = logging.getLogger(__name__)

# Patch socket module
try:
    IP_PKTINFO = socket.IP_PKTINFO
except AttributeError:
    IP_PKTINFO = 8


@dataclass
class BundleItem(object):
    ''' State for RX and TX full bundles.
    '''

    # The remote address
    address: str
    # The remote port
    port: int
    # Binary file to store in
    file: BinaryIO

    path_mtu: int
    ''' MTU for outgoing segments '''

    local_if: Optional[int] = None
    ''' Optional local interface index '''
    # Optional source address
    local_address: Optional[str] = None
    # Optional source port
    local_port: Optional[int] = None

    # The unique session ID number for TX bundles
    session_id: Optional[int] = None
    # Size of the bundle data
    total_length: Optional[int] = None

    sock_opts: List[Tuple] = field(default_factory=list)
    ''' Additional three-tuple of :py:meth:`socket.setsockopt` parameters '''


@dataclass
class Session(object):
    ''' State for segmented sessions.
    '''

    # The remote address
    address: str
    # The remote port
    port: int

    # The sending LTP Engine ID
    eng_id: int
    # Session ID
    sess_id: int
    # Total block size
    total_length: int
    # Total red part size
    red_length: int
    # Range of full data expected
    total_valid: Optional[portion.Interval] = None
    # Range of real data present
    valid: Optional[portion.Interval] = None
    # Accumulated byte string
    data: Optional[bytearray] = None

    @property
    def key(self):
        return tuple((self.address, self.port, self.sess_id))

    def validate(self, other):
        ''' Validate an other transfer against this base.
        '''
        if other.total_length != self.total_length:
            raise ValueError('Mismatched total length')


class AddressObject:
    ''' Interpret a text address as an `ipaddress` object.

    :param text: The input to convert.
    '''

    def __init__(self, text: Optional[str], proto=socket.IPPROTO_UDP):
        self.family = None
        self.ipaddr = None
        if text is None:
            return

        try:
            results = socket.getaddrinfo(text, None, proto=proto)
        except socket.gaierror:
            LOGGER.error('Failed to resolve address: %s', text)
            raise RuntimeError('Failed to resolve address: %s' % text)
        sockaddr = results[0][4]
        ipaddr = ipaddress.ip_address(sockaddr[0])
        LOGGER.debug('Resolved %s to IPv%d %s', text, ipaddr.version, ipaddr)

        self.family = socket.AF_INET if ipaddr.version == 4 else socket.AF_INET6
        self.ipaddr = ipaddr


@dataclass
class Conversation:
    ''' Bookkeep parameters of a UDP conversation
    which is address-and-port for each side.
    '''
    # Address family
    family: Optional[int] = None
    # The remote address
    peer_address: Optional[ipaddress._BaseAddress] = None
    # The remote port
    peer_port: Optional[int] = None
    local_if: Optional[int] = None
    ''' Local interface index '''
    # The local address
    local_address: Optional[ipaddress._BaseAddress] = None
    # The local port
    local_port: Optional[int] = None

    @staticmethod
    def pat_match(lt, rt):
        ''' Match tuples by-value or if one of the sides has None (i.e. unspecified).
        '''

        def val_match(pair):
            (lt, rt) = pair
            if lt == rt:
                return True
            return lt is None or rt is None

        return all(map(val_match, zip(lt, rt)))

    def find_in(self, dictlike, default=None):
        ''' Search a dictionary for exact-match or pattern-match.
        '''
        key = self.key
        if key in dictlike:
            return dictlike.get(key)

        for pair in dictlike.items():
            if Conversation.pat_match(pair[0], key):
                return pair[1]

        return default

    @property
    def key(self):
        return astuple(self)

    def make_local_socket(self):
        ''' Get a socket based on local requirements.
        :return: A UDP socket object.
        '''
        sock = socket.socket(self.family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self.local_address or self.local_port:
            if self.family == socket.AF_INET:
                sockaddr = (
                    str(self.local_address) if self.local_address else '0.0.0.0',
                    self.local_port or 0,
                )
            elif self.family == socket.AF_INET6:
                sockaddr = (
                    str(self.local_address) if self.local_address else '::',
                    self.local_port or 0,
                    0,
                    self.local_if or 0,
                )
            LOGGER.debug('make_local_socket bind to %s', sockaddr)
            sock.bind(sockaddr)

        if self.family == socket.AF_INET:
            sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
        elif self.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)

        return sock

    def get_peer_addr(self):
        ''' Get a peer address suitable for use with :py:meth:`socket.sendto`.
        :return: An address tuple.
        '''
        if isinstance(self.peer_address, ipaddress.IPv4Address):
            return (str(self.peer_address), self.peer_port)
        elif isinstance(self.peer_address, ipaddress.IPv6Address):
            return (str(self.peer_address), self.peer_port, 0, 0)
        else:
            raise RuntimeError('get_peer_addr without valid peer_address')


def range_encode(intvls: portion.Interval) -> List[int]:
    pairs = []
    seen_last = 0
    for intvl in intvls:
        pairs += [intvl.lower - seen_last, intvl.upper - intvl.lower]
        seen_last = intvl.upper
    return pairs


def range_decode(pairs: List[int]) -> portion.Interval:
    intvls = portion.empty()

    int_iter = iter(pairs)
    seen_last = 0
    while True:
        try:
            offset = next(int_iter)
            length = next(int_iter)
        except StopIteration:
            break

        low = seen_last + offset
        high = low + length

        seen_last = high
        intvls |= portion.closedopen(low, high)

    return intvls


class Agent(dbus.service.Object):
    ''' Overall agent behavior.

    :param config: The agent configuration object.
    :type config: :py:class:`Config`
    :param bus_kwargs: Arguments to :py:class:`dbus.service.Object` constructor.
        If not provided the default dbus configuration is used.
    :type bus_kwargs: dict or None
    '''

    DBUS_IFACE = 'org.ietf.dtn.ltpcl.Agent'

    def __init__(self, config: Config, bus_kwargs=None):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._config = config
        self._on_stop = None

        self._bindsocks = {}
        # Map from socket to glib io-watch ID
        self._listen_plain = {}
        # Existing sockets, map from `Conversation.key` to `socket.socket`
        self._plain_sock = {}

        self._tx_sess_id = random.randint(0, int(2**32))
        self._tx_queue = []
        # map from sender eng-id and sess-id to session
        self._rx_fragments: Dict[Tuple[int, int], Session] = {}
        self._rx_id = 0
        self._rx_queue = {}

        if bus_kwargs is None:
            bus_kwargs = dict(
                conn=config.bus_conn,
                object_path='/org/ietf/dtn/ltpcl/Agent'
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
            self.listen(item.address, item.port, item.opts)

        self.__logger.info('Running as engine ID: %d', self._config.engine_id)

    def is_transfer_idle(self):
        ''' Determine if the agent is idle.

        :return: True if there are no data being processed RX or TX side.
        '''
        return len(self._rx_queue) == 0 and len(self._tx_queue) == 0

    def set_on_stop(self, func):
        ''' Set a callback to be run when this agent is stopped.

        :param func: The callback, which takes no arguments.
        '''
        self._on_stop = func

    @dbus.service.method(DBUS_IFACE, in_signature='')
    def stop(self):
        ''' Immediately stop the agent and disconnect any sessions. '''
        self.__logger.info('Stopping agent')
        for spec in tuple(self._bindsocks.keys()):
            conv = Conversation(*spec)
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

    @dbus.service.method(DBUS_IFACE, in_signature='sia{sv}')
    def listen(self, address, port, opts=None):
        ''' Begin listening for incoming transfers and defer handling
        connections to `glib` event loop.
        '''
        if opts is None:
            opts = {}

        addrobj = AddressObject(address)
        conv = Conversation(
            family=addrobj.family,
            local_address=addrobj.ipaddr,
            local_port=port
        )
        if conv.key in self._bindsocks:
            raise dbus.DBusException('Already listening')

        sock = conv.make_local_socket()
        self.__logger.info('Listening on %s:%d', conv.local_address, conv.local_port)

        if conv.family == socket.AF_INET:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)

        multicast_member = opts.get('multicast_member', [])
        for item in multicast_member:
            addr = str(item['addr'])

            if conv.family == socket.AF_INET:
                self.__logger.info('Listening for multicast %s', addr)
                # mreq = struct.pack("=4sl", socket.inet_aton(addr), socket.INADDR_ANY)
                mreq = (
                    socket.inet_pton(socket.AF_INET, addr)
                    + socket.inet_pton(socket.AF_INET, '0.0.0.0')
                )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            else:
                iface = item.get('iface')
                iface_ix = socket.if_nametoindex(iface) if iface else 0
                self.__logger.info('Listening for multicast %s on %s (%s)', addr, iface, iface_ix)
                mreq = (
                    socket.inet_pton(socket.AF_INET6, addr)
                    + struct.pack("@I", iface_ix)
                )
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

        self._bindsocks[conv.key] = sock
        self._listen_plain[sock] = glib.io_add_watch(sock, glib.IO_IN, self._sock_recvfrom)

    @dbus.service.method(DBUS_IFACE, in_signature='sq')
    def listen_stop(self, address, port):
        ''' Stop listening for transfers on an existing port binding.
        '''
        addrobj = AddressObject(address)
        conv = Conversation(
            family=addrobj.family,
            local_address=addrobj.ipaddr,
            local_port=port
        )
        self._listen_stop(conv)

    def _listen_stop(self, conv):
        if conv.key not in self._bindsocks:
            raise dbus.DBusException('Not listening')

        sock = self._bindsocks.pop(conv.key)
        self.__logger.info('Un-listening on %s:%d', conv.local_address, conv.local_port)
        if sock in self._listen_plain:
            glib.source_remove(self._listen_plain.pop(sock))
        sock.close()

    def _sock_recvfrom(self, sock, *_args, **_kwargs):
        ''' Callback to handle incoming datagrams.

        :return: True to continue listening.
        '''
        datalen = 64 * 1024
        anclen = 0
        if sock.family == socket.AF_INET:
            anclen += (
                # space for TOS `int`
                socket.CMSG_SPACE(struct.calcsize('@I'))
                # space for PKTINFO `in_pktinfo`
                + socket.CMSG_SPACE(struct.calcsize('@I') + 4 + 4)
            )
        elif sock.family == socket.AF_INET6:
            anclen += (
                # space for TCLASS `int`
                socket.CMSG_SPACE(struct.calcsize('@I'))
                # space for PKTINFO `struct in6_pktinfo`
                + socket.CMSG_SPACE(16 + struct.calcsize('@I'))
            )
        data, ancdata, _msg_flags, fromaddr = sock.recvmsg(datalen, anclen)
        localaddr = sock.getsockname()

        self.__logger.debug('With ancdata %s', ancdata)
        dst_addr = None
        for (cmsg_level, cmsg_type, cmsg_data) in ancdata:
            key = (cmsg_level, cmsg_type)
            if key == (socket.IPPROTO_IP, IP_PKTINFO):
                (iface_ix, _, dst_addr) = struct.unpack('@I4s4s', cmsg_data)
                dst_addr = ipaddress.IPv4Address(dst_addr)
                self.__logger.debug('ancdata in_pktinfo %s %s', dst_addr, iface_ix)
            elif key == (socket.IPPROTO_IPV6, socket.IPV6_PKTINFO):
                (dst_addr, iface_ix) = struct.unpack('@16sI', cmsg_data)
                dst_addr = ipaddress.IPv6Address(dst_addr)
                self.__logger.debug('ancdata in6_pktinfo %s %s', dst_addr, iface_ix)

        peer_addrobj = AddressObject(fromaddr[0])
        local_addrobj = AddressObject(localaddr[0])
        conv = Conversation(
            family=peer_addrobj.family,
            peer_address=peer_addrobj.ipaddr,
            peer_port=fromaddr[1],
            local_address=(dst_addr or local_addrobj.ipaddr),
            local_port=localaddr[1]
        )

        self.__logger.info('Received %d octets via plain on %s',
                           len(data), conv)
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if (cmsg_level, cmsg_type) == (socket.IPPROTO_IP, socket.IP_TOS):
                self.__logger.info('With TOS field %02x', cmsg_data[0])
        self._plain_sock[conv.key] = sock
        self._recv_datagram(sock, data, conv, ip_tos)
        return True

    def _recv_datagram(self, sock, data: bytes, conv: Conversation, ip_tos: int = 0):
        timestamp = datetime.now(timezone.utc)

        # Sequential data source
        buf = BufferedReader(BytesIO(data))
        seg_count = 0
        while True:
            first_data = buf.peek(1)
            if not first_data:
                break
            seg_count += 1

            # FIXME handle LTP segments

        self.__logger.debug('Handled %d messages from packet', seg_count)

    def _add_rx_item(self, item: BundleItem):
        ''' Add a received bundle.
        '''

        metadata = {
            'address': item.address,
            'port': item.port,
        }
        if item.local_address:
            metadata['local_address'] = item.local_address
        if item.local_port:
            metadata['local_port'] = item.local_port

        self._rx_queue[item.transfer_id] = item
        self.recv_bundle_finished(str(item.transfer_id), item.total_length, metadata)

    @dbus.service.signal(DBUS_IFACE, signature='sta{sv}')
    def recv_bundle_finished(self, bid, length, metadata):
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
            port=int(tx_params.get('port', 1113)),
            local_if=(int(tx_params['local_if']) if 'local_if' in tx_params else None),
            local_address=(str(tx_params['local_address']) if 'local_address' in tx_params else None),
            local_port=(int(tx_params['local_port']) if 'local_port' in tx_params else None),
            path_mtu=(int(tx_params['mtu'] if 'mtu' in tx_params else self._config.mtu_default)),
            file=file
        )
        return str(self._add_tx_item(item))

    @dbus.service.method(DBUS_IFACE, in_signature='aya{sv}', out_signature='s')
    def send_bundle_data(self, data: bytes, tx_params: Dict):
        ''' Send bundle data directly.
        '''
        # byte array to bytes
        data = b''.join([bytes([val]) for val in data])
        tx_params = dict(tx_params)
        self.__logger.debug('send_bundle_data data len %d, tx_params %s', len(data), tx_params)
        return self.send_bundle_fileobj(BytesIO(data), tx_params)

    def _add_tx_item(self, item: BundleItem):
        item.session_id = copy.copy(self._tx_sess_id)
        self._tx_sess_id += 1

        item.file.seek(0, os.SEEK_END)
        item.total_length = item.file.tell()
        item.file.seek(0)

        self._tx_queue.append(item)
        self._process_tx_queue_trigger()
        return item.session_id

    def _process_tx_queue_trigger(self):
        if self._tx_queue:
            glib.idle_add(self._process_tx_queue)

    def _send_transfer(self, sender, item: BundleItem):
        ''' Send a transfer, segmenting as necessary.

        :param sender: A datagram sending function.
        :param item: The item to send.
        :type item: :py:cls:`BundleItem`
        '''
        block = item.file.read()
        block += block  # dupe

        segments = []
        self.__logger.info('Session %d block size %d relative to MTU %s',
                           item.session_id, len(block), item.path_mtu)

        # The base data segment with the largest values present
        seg_base = ltp.LTP(
            flags=3,  # Red EOB
            SessionOriginator=self._config.engine_id,
            SessionNumber=item.session_id,
            DATA_ClientServiceID=127,
            DATA_PayloadOffset=len(block),
            DATA_PayloadLength=len(block),
            LTP_Payload=b'',  # not real
        )
        seg_base_encsize = len(bytes(seg_base))
        # Size left for fragment data
        remain_size = item.path_mtu - seg_base_encsize

        seg_offset = 0
        while seg_offset < len(block):
            end_offset = min(seg_offset + remain_size, item.total_length)

            if False:
                # red data
                block_type = 3 if end_offset == item.total_length else 0
            else:
                # green data
                block_type = 7 if end_offset == item.total_length else 4

            seg = bytes(ltp.LTP(
                flags=block_type,
                SessionOriginator=self._config.engine_id,
                SessionNumber=item.session_id,
                DATA_ClientServiceID=1,
                DATA_PayloadOffset=seg_offset,
                LTP_Payload=block[seg_offset:(seg_offset + remain_size)],
            ))
            seg_offset += remain_size
            segments.append(seg)

        for seg in segments:
            self.__logger.debug('Sending datagram size %d', len(seg))
            sender(seg)

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

        self.send_bundle_started(
            str(item.session_id),
            item.total_length
        )

        peer_addrobj = AddressObject(item.address)
        local_addrobj = AddressObject(item.local_address or self._config.default_tx_address)
        conv = Conversation(
            family=peer_addrobj.family,
            peer_address=peer_addrobj.ipaddr,
            peer_port=item.port,
            local_if=item.local_if,
            local_address=local_addrobj.ipaddr,
            local_port=(item.local_port or self._config.default_tx_port)
        )
        self.__logger.info('Sending %d octets on %s', item.total_length, conv)

        sock = conv.find_in(self._plain_sock)
        if sock is None:
            self.__logger.debug('New conversation seen %s', conv)
            sock = conv.make_local_socket()
            self._plain_sock[conv.key] = sock

        # Listen for any return-path regardless
        if sock not in self._listen_plain:
            self._listen_plain[sock] = glib.io_add_watch(sock, glib.IO_IN, self._sock_recvfrom)

        ancdata = []

        # Direct socket options
        for opt in item.sock_opts:
            sock.setsockopt(*opt)

        def simplesender(data):
            ''' Send to a single destination
            '''
            sockaddr = conv.get_peer_addr()
            self.__logger.debug('With ancdata %s', ancdata)
            sock.sendmsg([data], ancdata, 0, sockaddr)

        if conv.peer_address.is_multicast:
            multicast = self._config.multicast

            loop = 0
            if loop is not None:
                if conv.family == socket.AF_INET:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
                else:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, loop)

            if multicast.ttl is not None:
                if conv.family == socket.AF_INET:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, multicast.ttl)
                else:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, multicast.ttl)

            sender = simplesender

        else:
            # unicast transfer
            sender = simplesender

        # only allow fragmentation of transfers
        self._send_transfer(sender, item)

        self.send_bundle_finished(
            str(item.session_id),
            item.total_length,
            'success'
        )

        return bool(self._tx_queue)

    @dbus.service.signal(DBUS_IFACE, signature='st')
    def send_bundle_started(self, bid, length):
        pass

    @dbus.service.signal(DBUS_IFACE, signature='sts')
    def send_bundle_finished(self, bid, length, result):
        pass
