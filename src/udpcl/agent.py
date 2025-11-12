'''
Implementation of a symmetric UDPCL agent.
'''
import copy
from dataclasses import dataclass, astuple, field
from datetime import datetime, timedelta, timezone
import enum
from typing import Optional, BinaryIO, List, Tuple
import ipaddress
import logging
import os
from io import BytesIO, BufferedReader
import secrets
import socket
import struct
import cbor2
import portion
import dbus.service
from gi.repository import GLib as glib
from udpcl.config import PollConfig
from bp.encoding.fields import DtnTimeField

from udpcl.config import Config, ListenConfig

LOGGER = logging.getLogger(__name__)

# Patch socket module
try:
    IP_PKTINFO = socket.IP_PKTINFO
except AttributeError:
    IP_PKTINFO = 8

IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT = 0
IP_PMTUDISC_WANT = 1
IP_PMTUDISC_DO = 2  # Always DF
IP_PMTUDISC_PROBE = 3  # DF and ignore MTU

''' Delay in milliseconds '''
ECN_NOECT = 0x00
ECN_ECT1 = 0x01
ECN_ECT0 = 0x02
ECN_CE = 0x03


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

    local_if: Optional[int] = None
    ''' Optional local interface index '''
    # Optional source address
    local_address: Optional[str] = None
    # Optional source port
    local_port: Optional[int] = None
    # The unique transfer ID number.
    transfer_id: Optional[int] = None
    # Size of the bundle data
    total_length: Optional[int] = None

    ip_tos: int = 0
    ''' The whole TOS (DSCP + ECN bits) '''
    sock_opts: List[Tuple] = field(default_factory=list)
    ''' Additional three-tuple of :py:meth:`socket.setsockopt` parameters '''


@dataclass
class Transfer(object):
    ''' State for fragmented transfers.
    '''

    # The remote address
    address: str
    # The remote port
    port: int
    # Transfer ID
    xfer_id: int
    # Total transfer size
    total_length: int
    # Range of full data expected
    total_valid: Optional[portion.Interval] = None
    # Range of real data present
    valid: Optional[portion.Interval] = None
    # Accumulated byte string
    data: Optional[bytearray] = None

    @property
    def key(self):
        return tuple((self.address, self.port, self.xfer_id))

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
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
            sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
        elif self.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVTCLASS, 1)
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


@dataclass
class EcnCounts:
    ''' Count of ECN codepoints from a peer address. '''
    ect0: int = 0
    ect1: int = 0
    ce: int = 0


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

    DBUS_IFACE = 'org.ietf.dtn.udpcl.Agent'

    def __init__(self, config, bus_kwargs=None):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._config = config
        self._on_stop = None

        self._bindsocks = {}
        # Map from socket to glib io-watch ID
        self._listen_plain = {}
        # Existing sockets, map from `Conversation.key` to `socket.socket`
        self._plain_sock = {}
        # In-progress DTLS handshakes, map from `Conversation.key` to `socket.socket`
        self._dtls_prep = {}
        # Existing DTLS sessions, map from `Conversation.key` to `dtls.SSLConnection`
        self._dtls_sess = {}

        self._tx_id = 0
        self._tx_queue = []
        # map from transfer ID to :py:cls:`Transfer`
        self._rx_fragments = {}
        self._rx_id = 0
        self._rx_queue = {}

        self._pmtud_recv = {}
        self._pmtud_send = {}

        # Map from sending peer address to EcnCounts
        self._ecn_state = {}

        if bus_kwargs is None:
            bus_kwargs = dict(
                conn=config.bus_conn,
                object_path='/org/ietf/dtn/udpcl/Agent'
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
        for item in self._config.polling:
            self.polling_start(item)

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

    def polling_start(self, item: PollConfig):
        self.__logger.info('Polling start to %s at interval %sms', item.address, item.interval_ms)
        tid = glib.timeout_add(item.interval_ms, self._poll, item, True)
        if item.interval_ms > 2000:
            # First one immediately
            glib.timeout_add(1000, self._poll, item, False)
        return tid

    @dbus.service.signal(DBUS_IFACE, signature='xissq')
    def polling_received(self, dtntime, interval_ms, node_id, address, port):
        ''' Signal when a receive-path accept is received.
        '''

    def _poll(self, item: PollConfig, repeat: bool):
        ''' Send a return-path accept message.
        '''
        data = cbor2.dumps({
            ExtensionKey.SENDER_LISTEN: item.interval_ms,
            ExtensionKey.SENDER_NODEID: self._config.node_id,
        })
        item = BundleItem(
            address=item.address,
            port=item.port,
            local_address=item.local_address,
            local_port=item.local_port,
            file=BytesIO(data),
        )
        self._add_tx_item(item, is_transfer=False)
        return repeat

    def _get_tos(self, is_data: bool) -> int:
        ''' Get the TOS byte for IP headers '''
        if self._config.ecn_init:
            return ECN_ECT0
        else:
            return ECN_NOECT

    @dbus.service.method(DBUS_IFACE, in_signature='sqi')
    def pmtud_start(self, address, port, stepcount):
        addrobj = AddressObject(address)

        base_plpmtu = 1200
        if addrobj.family == socket.AF_INET:
            txp_overhead = 20 + 8
            min_plpmtu = 68 - txp_overhead
        else:
            txp_overhead = 40 + 8
            min_plpmtu = 1280 - txp_overhead
        max_plpmtu = min(2 * base_plpmtu, 2 ** 16 - 1) - txp_overhead

        pkt_step = max(1, (max_plpmtu - min_plpmtu) // stepcount)
        nonce = secrets.randbits(32)
        confirm_delay = timedelta(milliseconds=1000)
        self.__logger.debug('Sending PMTUD probes to %s for %s:%s', address, nonce, stepcount)

        size_map = {
            seq_no: pkt_size for seq_no, pkt_size
            in enumerate(range(base_plpmtu, max_plpmtu, pkt_step))
        }

        state = {
            'seq_nos': size_map,
        }
        self._pmtud_send[nonce] = state

        for seq_no, pkt_size in size_map.items():
            msg = cbor2.dumps({
                ExtensionKey.PEER_PROBE: [
                    nonce,
                    seq_no,
                    confirm_delay // timedelta(milliseconds=1)
                ],
            })
            # Pad out the packet
            data = msg + b'\0' * (pkt_size - len(msg))

            item = BundleItem(
                address=address,
                port=port,
                ip_tos=self._get_tos(is_data=True),
                file=BytesIO(data),
                sock_opts=[(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE)],
            )
            self._add_tx_item(item, is_transfer=False)

    def _pmtud_recv_probe(self, conv: Conversation, ext):
        (nonce, seq_no, confirm_delay) = ext
        self.__logger.debug('Received PMTUD probe %s:%s from %s', nonce, seq_no, conv.peer_address)

        state = self._pmtud_recv.get(conv.key)
        if state is None:
            state = {
                'timer': None,
                'seq_nos': portion.empty(),
            }
            self._pmtud_recv[conv.key] = state

        # Cancel any earlier timer and queue the next timeout
        if state['timer'] is not None:
            glib.source_remove(state['timer'])

        state['nonce'] = nonce
        state['seq_nos'] |= portion.closedopen(seq_no, seq_no + 1)
        state['timer'] = glib.timeout_add(confirm_delay, self._pmtud_send_confirm, conv)

    def _pmtud_send_confirm(self, conv: Conversation):
        state = self._pmtud_recv[conv.key]
        del self._pmtud_recv[conv.key]
        nonce = state['nonce']
        seq_nos = state['seq_nos']

        self.__logger.debug('Sending PMTUD ack %s:%s to %s', nonce, seq_nos, conv.peer_address)
        seen_offsets = range_encode(seq_nos)
        msg = cbor2.dumps({
            ExtensionKey.PEER_CONFIRM: [nonce, seen_offsets],
        })

        item = BundleItem(
            address=str(conv.peer_address),
            port=conv.peer_port,
            file=BytesIO(msg),
        )
        self._add_tx_item(item, is_transfer=False)

    def _pmtud_recv_confirm(self, conv: Conversation, ext):
        (nonce, seen_offsets) = ext

        state = self._pmtud_send.get(nonce)
        if state is None:
            return
        del self._pmtud_send[nonce]

        seq_nos = range_decode(seen_offsets)
        seen_sizes = [
            state['seq_nos'][seq_no]
            for seq_no in portion.iterate(seq_nos, step=1)
        ]
        self.__logger.debug('Received PMTUD ack %s:%s to %s for sizes %s',
                            nonce, seq_nos, conv.peer_address, seen_sizes)

    def _ecn_recvfrom(self, conv: Conversation, ip_ecn: int):
        # aggregate of all packets from the same peer, regardless of destination
        ecn_key = (conv.peer_address, conv.peer_port)

        if ecn_key not in self._ecn_state:
            self.__logger.debug('Received ECN marking 0x%02x in new conversation %s', ip_ecn, conv)
            counts = EcnCounts()
            state = {
                'counts': counts,
                'timer': None,
                'last': None,
            }
            self._ecn_state[ecn_key] = state
        else:
            state = self._ecn_state[ecn_key]
            counts = state['counts']

        if ip_ecn == ECN_ECT0:
            counts.ect0 += 1
        elif ip_ecn == ECN_ECT1:
            counts.ect1 += 1
        elif ip_ecn == ECN_CE:
            counts.ce += 1

        if state['timer'] is not None:
            glib.source_remove(state['timer'])
        delay = self._config.ecn_feedback_delay // timedelta(milliseconds=1)
        state['timer'] = glib.timeout_add(delay, self._ecn_sendto, ecn_key)

        if state['last'] is not None:
            diff = state['last'] - datetime.now(timezone.utc)
            if diff > self._config.ecn_feedback_delay:
                self._ecn_sendto(ecn_key)

    def _ecn_sendto(self, ecn_key: Tuple):
        state = self._ecn_state[ecn_key]
        counts = state['counts']

        msg = cbor2.dumps({
            ExtensionKey.ECN_COUNTS: [counts.ect0, counts.ect1, counts.ce],
        })

        item = BundleItem(
            address=str(ecn_key[0]),
            port=ecn_key[1],
            file=BytesIO(msg),
        )
        self._add_tx_item(item, is_transfer=False)

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
        ip_tos = 0
        for (cmsg_level, cmsg_type, cmsg_data) in ancdata:
            key = (cmsg_level, cmsg_type)
            if key == (socket.IPPROTO_IP, socket.IP_TOS):
                ip_tos = cmsg_data[0]
                self.__logger.debug('ancdata TOS 0x%02x', ip_tos)
            elif key == (socket.IPPROTO_IP, IP_PKTINFO):
                (iface_ix, _, dst_addr) = struct.unpack('@I4s4s', cmsg_data)
                dst_addr = ipaddress.IPv4Address(dst_addr)
                self.__logger.debug('ancdata in_pktinfo %s %s', dst_addr, iface_ix)
            elif key == (socket.IPPROTO_IPV6, socket.IPV6_TCLASS):
                (ip_tos,) = struct.unpack('@I', cmsg_data)
                self.__logger.debug('ancdata TCLASS 0x%02x', ip_tos)
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
        if conv.key in self._dtls_prep or conv.key in self._dtls_sess:
            self.__logger.debug('Ignorning %d octets from DTLS handshake',
                                len(data))
            return True

        ip_ecn = ip_tos & 0x03
        if ip_ecn and self._config.ecn_feedback:
            self._ecn_recvfrom(conv, ip_ecn)

        self.__logger.info('Received %d octets via plain on %s',
                           len(data), conv)
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if (cmsg_level, cmsg_type) == (socket.IPPROTO_IP, socket.IP_TOS):
                self.__logger.info('With TOS field %02x', cmsg_data[0])
        self._plain_sock[conv.key] = sock
        self._recv_datagram(sock, data, conv, ip_tos)
        return True

    def _starttls(self, sock, conv: Conversation, server_side: bool):
        self._dtls_prep[conv.key] = sock

        # Create a bound-on-both-sides socket which will preferentially
        # receive datagrams for this conversation
        conn = socket.socket(sock.family, sock.type, sock.proto)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        conn.bind(sock.getsockname())
        conn.connect(conv.get_peer_addr())

        LOGGER.info('STARTTLS for %s', conv)
        conn = self._config.get_ssl_connection(conn, server_side=server_side)
        if server_side:
            pass  # conn.listen()
        else:
            # as client
            conn.connect(conv.get_peer_addr())

        self.__logger.info('Starting DTLS handshake on %s', sock)
        conn.do_handshake()
        # after establishment
        del self._dtls_prep[conv.key]
        self._dtls_sess[conv.key] = conn

        glib.io_add_watch(
            conn.get_socket(inbound=True),
            glib.IO_IN,
            self._dtlsconn_recv,
            conn, conv
        )

        return conn

    def _dtlsconn_recv(self, _src, _cond, conn, conv: Conversation, *_args, **_kwargs):
        data = conn.read(64 * 1024)
        self.__logger.info('Received %d octets via DTLS on %s',
                           len(data), conv)
        self._recv_datagram(None, data, conv)
        return True

    def _recv_datagram(self, sock, data: bytes, conv: Conversation, ip_tos: int = 0):
        DTLS_FIRST_OCTETS = (
            20,  # change_cipher_spec
            21,  # alert
            22,  # handshake
            23,  # application_data
        )
        timestamp = datetime.now(timezone.utc)

        # Sequential data source
        buf = BufferedReader(BytesIO(data))
        msg_count = 0
        while True:
            first_data = buf.peek(1)
            if not first_data:
                break
            msg_count += 1

            first_octet = first_data[0]
            major_type = first_octet >> 5
            self.__logger.debug('Decoding message with first octet 0x%02x (major type %d)', first_octet, major_type)
            if first_octet == 0x00:
                self.__logger.info('Ignoring padding to end of packet')
                buf.seek(0, os.SEEK_END)

            elif first_octet in DTLS_FIRST_OCTETS:
                self.__logger.error('Unexpected DTLS handshake')
                if sock:
                    self._starttls(sock, conv, server_side=True)
                else:
                    self.__logger.error('Ignored DTLS message *within* DTLS plaintext')
                buf.seek(0, os.SEEK_END)

            elif first_octet == 0x06:
                if sock and self._config.require_tls:
                    self.__logger.error('Rejecting non-secured bundle')
                    return

                self.__logger.error('Ignoring BPv6 bundle and remainder of packet')
                buf.seek(0, os.SEEK_END)

            elif major_type == 4:
                if sock and self._config.require_tls:
                    self.__logger.error('Rejecting non-secured bundle')
                    return

                # Scan the single bundle message
                off_start = buf.tell()
                cbor2.load(buf)
                off_end = buf.tell()
                msg_data = data[off_start:off_end]

                self._add_rx_item(
                    BundleItem(
                        address=str(conv.peer_address),
                        port=conv.peer_port,
                        ip_tos=ip_tos,
                        total_length=len(msg_data),
                        file=BytesIO(msg_data)
                    )
                )

            elif major_type == 5:
                # Map type
                extmap = cbor2.load(buf)
                self._recv_ext_map(sock, extmap, conv, timestamp)

            else:
                self.__logger.error('Unknown message type with first octet 0x%02x, ignoring remainder of packet', first_octet)
                buf.seek(0, os.SEEK_END)

        self.__logger.debug('Handled %d messages from packet', msg_count)

    def _recv_ext_map(self, sock, extmap: dict, conv: Conversation, timestamp: datetime):
        if ExtensionKey.STARTTLS in extmap:
            if sock:
                self._starttls(sock, conv, server_side=True)
            else:
                self.__logger.error('Ignored STARTTLS *within* DTLS plaintext')

        elif sock and self._config.require_tls:
            self.__logger.error('Rejecting non-secured extension map')
            return

        if ExtensionKey.SENDER_LISTEN in extmap:
            interval_ms = int(extmap[ExtensionKey.SENDER_LISTEN])
            node_id = extmap.get(ExtensionKey.SENDER_NODEID, '')
            self.__logger.info('Sender Listen for %d ms from %s', interval_ms, node_id)

            data = cbor2.dumps({
                ExtensionKey.SENDER_NODEID: self._config.node_id,
            })
            item = BundleItem(
                address=str(conv.peer_address),
                port=conv.peer_port,
                local_address=str(conv.local_address) if conv.local_address else None,
                local_port=conv.local_port,
                file=BytesIO(data),
            )
            self._add_tx_item(item, is_transfer=False)

            dtntime = DtnTimeField.datetime_to_dtntime(timestamp)
            self.polling_received(dtntime, interval_ms, node_id, str(conv.peer_address), conv.peer_port)

        if ExtensionKey.TRANSFER in extmap:
            xfer_id, total_len, frag_offset, frag_data = extmap[ExtensionKey.TRANSFER]
            new_xfer = Transfer(
                address=str(conv.peer_address),
                port=conv.peer_port,
                xfer_id=xfer_id,
                total_length=total_len,
            )

            xfer = self._rx_fragments.get(new_xfer.key)
            if xfer:
                xfer.validate(new_xfer)
            else:
                xfer = new_xfer
                self._rx_fragments[xfer.key] = xfer
                xfer.total_valid = portion.closedopen(0, xfer.total_length)
                xfer.valid = portion.empty()
                xfer.data = bytearray(xfer.total_length)

            self.__logger.debug('Handling transfer %d fragment offset %d size %d', xfer.xfer_id, frag_offset, len(frag_data))
            end_ix = frag_offset + len(frag_data)
            xfer.data[frag_offset:end_ix] = frag_data

            xfer.valid |= portion.closedopen(frag_offset, end_ix)
            if xfer.valid == xfer.total_valid:
                self.__logger.info('Finished transfer %d size %d', xfer.xfer_id, xfer.total_length)
                del self._rx_fragments[xfer.key]
                self._add_rx_item(
                    BundleItem(
                        address=xfer.address,
                        port=xfer.port,
                        total_length=xfer.total_length,
                        file=BytesIO(xfer.data)
                    )
                )

        if ExtensionKey.PEER_PROBE in extmap:
            self._pmtud_recv_probe(conv, extmap[ExtensionKey.PEER_PROBE])
        if ExtensionKey.PEER_CONFIRM in extmap:
            self._pmtud_recv_confirm(conv, extmap[ExtensionKey.PEER_CONFIRM])

    def _add_rx_item(self, item: BundleItem):
        ''' Add a recevied bundle.
        '''
        if item.transfer_id is None:
            item.transfer_id = copy.copy(self._rx_id)
            self._rx_id += 1

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
            port=int(tx_params.get('port', 4556)),
            local_if=(int(tx_params['local_if']) if 'local_if' in tx_params else None),
            local_address=(str(tx_params['local_address']) if 'local_address' in tx_params else None),
            local_port=(int(tx_params['local_port']) if 'local_port' in tx_params else None),
            ip_tos=self._get_tos(is_data=True),
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

    def _send_transfer(self, sender, item):
        ''' Send a transfer, fragmenting if necessary.

        :param sender: A datagram sending function.
        :param item: The item to send.
        :type item: :py:cls:`BundleItem`
        '''
        mtu = self._config.mtu_default
        data = item.file.read()

        segments = []
        self.__logger.info('Transfer %d size %d relative to MTU %s',
                           item.transfer_id, len(data), mtu)
        if mtu is None or len(data) < mtu:
            segments = [data]
        else:
            # The base extension map with the largest values present
            ext_base = {
                ExtensionKey.TRANSFER: [
                    item.transfer_id,
                    item.total_length,
                    item.total_length,
                    b'',
                ],
            }
            ext_base_encsize = len(cbor2.dumps(ext_base))
            # Largest bstr head size
            data_size_encsize = len(cbor2.dumps(item.total_length))
            # Size left for fragment data
            remain_size = mtu - (ext_base_encsize - 1 + data_size_encsize)

            frag_offset = 0
            while frag_offset < len(data):
                ext = {
                    ExtensionKey.TRANSFER: [
                        item.transfer_id,
                        item.total_length,
                        frag_offset,
                        data[frag_offset:(frag_offset + remain_size)],
                    ],
                }
                frag_offset += remain_size
                segments.append(cbor2.dumps(ext))

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
        item = self._tx_queue.pop(0)

        if item.transfer_id is not None:
            self.send_bundle_started(
                str(item.transfer_id),
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

        if conv.family == socket.AF_INET:
            ancdata.append((socket.IPPROTO_IP, socket.IP_TOS, struct.pack('@I', item.ip_tos)))
        elif conv.family == socket.AF_INET6:
            ancdata.append((socket.IPPROTO_IPV6, socket.IPV6_TCLASS, struct.pack('@I', item.ip_tos)))

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

            if self._config.dtls_enable_tx:
                conn = self._dtls_sess.get(conv.key)
                if conn:
                    self.__logger.debug('Using existing session with %s', conv)
                else:
                    self.__logger.debug('Need new session with %s', conv)
                    sock.sendto(cbor2.dumps({ExtensionKey.STARTTLS: None}), conv.get_peer_addr())
                    conn = self._starttls(sock, conv, server_side=False)
                sender = conn.write
            else:
                sender = simplesender

        if item.transfer_id is not None:
            # only allow fragmentation of transfers
            self._send_transfer(sender, item)
        else:
            sender(item.file.read())

        if item.transfer_id is not None:
            self.send_bundle_finished(
                str(item.transfer_id),
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
