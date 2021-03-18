'''
Implementation of a symmetric UDPCL agent.
'''
import copy
from dataclasses import dataclass, astuple
from datetime import datetime, timezone
import enum
from typing import Optional, BinaryIO
import ipaddress
import logging
import os
from io import BytesIO
import socket
import struct
import cbor2
import portion
import dbus.service
from gi.repository import GLib as glib
from udpcl.config import PollConfig
from bp.encoding.fields import DtnTimeField
LOGGER = logging.getLogger(__name__)


@enum.unique
class ExtensionKey(enum.IntFlag):
    ''' Extension map keys.
    '''
    TRANSFER = 0x02
    RETURN_ACCEPT = 0x03
    SENDER_NODEID = 0x04
    STARTTLS = 0x05


@dataclass
class BundleItem(object):
    ''' State for RX and TX full bundles.
    '''

    #: The remote address
    address: str
    #: The remote port
    port: int
    #: Binary file to store in
    file: BinaryIO
    #: Optional source address
    local_addr: Optional[str] = None
    #: Optional source port
    local_port: Optional[int] = None
    #: The unique transfer ID number.
    transfer_id: Optional[int] = None
    #: Size of the bundle data
    total_length: Optional[int] = None


@dataclass
class Transfer(object):
    ''' State for fragmented transfers.
    '''

    #: The remote address
    address: str
    #: The remote port
    port: int
    #: Transfer ID
    xfer_id: int
    #: Total transfer size
    total_length: int
    # Range of full data expected
    total_valid: Optional[portion.Interval] = None
    #: Range of real data present
    valid: Optional[portion.Interval] = None
    #: Accumulated byte string
    data: Optional[bytearray] = None

    @property
    def key(self):
        return tuple((self.address, self.port, self.xfer_id))

    def validate(self, other):
        ''' Validate an other transfer against this base.
        '''
        if other.total_length != self.total_length:
            raise ValueError('Mismatched total length')


@dataclass
class Conversation:
    ''' Bookkeep parameters of a UDP conversation
    which is address-and-port for each side.
    '''
    #: The remote address
    peer_address: Optional[ipaddress._BaseAddress] = None
    #: The remote port
    peer_port: Optional[int] = None
    #: The local address
    local_address: Optional[ipaddress._BaseAddress] = None
    #: The local port
    local_port: Optional[int] = None

    @staticmethod
    def addr_from_str(address: Optional[str]):
        if address is None:
            return None
        return ipaddress.ip_address(address)

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

    @property
    def is_ipv4(self):
        return (
            isinstance(self.peer_address, ipaddress.IPv4Address)
            or isinstance(self.local_address, ipaddress.IPv4Address)
        )

    def make_local_socket(self):
        ''' Get a socket based on local requirements.
        :return: A UDP socket object.
        '''
        if self.is_ipv4:
            family = socket.AF_INET
        else:
            family = socket.AF_INET6

        sock = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self.local_address or self.local_port:
            address = str(self.local_address) if self.local_address else ''
            port = self.local_port or 0
            sock.bind((address, port))

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
        #: Map from socket to glib io-watch ID
        self._listen_plain = {}
        # Existing sockets, map from `Conversation.key` to `socket.socket`
        self._plain_sock = {}
        # Existing DTLS sessions, map from `Conversation.key` to `dtls.SSLConnection`
        self._dtls_sess = {}

        self._tx_id = 0
        self._tx_queue = []
        #: map from transfer ID to :py:cls:`Transfer`
        self._rx_fragments = {}
        self._rx_id = 0
        self._rx_queue = {}

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
            self.listen_stop(*spec)

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

        conv = Conversation(
            local_address=ipaddress.ip_address(address),
            local_port=port
        )
        if conv.key in self._bindsocks:
            raise dbus.DBusException('Already listening')

        sock = conv.make_local_socket()
        self.__logger.info('Listening on %s:%d', address or '*', port)

        multicast_member = opts.get('multicast_member', [])
        for item in multicast_member:
            addr = str(item['addr'])

            if conv.is_ipv4:
                self.__logger.info('Listening for multicast %s', addr)
                #mreq = struct.pack("=4sl", socket.inet_aton(addr), socket.INADDR_ANY)
                mreq = (
                    socket.inet_pton(socket.AF_INET, addr)
                    +socket.inet_pton(socket.AF_INET, '0.0.0.0')
                )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            else:
                iface = item['iface']
                iface_ix = socket.if_nametoindex(iface)
                self.__logger.info('Listening for multicast %s on %s (%s)', addr, iface, iface_ix)
                mreq = (
                    socket.inet_pton(socket.AF_INET6, addr)
                    +struct.pack("@I", iface_ix)
                )
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

        self._bindsocks[conv.key] = sock
        self._listen_plain[sock] = glib.io_add_watch(sock, glib.IO_IN, self._sock_recvfrom)

    @dbus.service.method(DBUS_IFACE, in_signature='si')
    def listen_stop(self, address, port):
        ''' Stop listening for transfers on an existing port binding.
        '''
        conv = Conversation(
            local_address=ipaddress.ip_address(address),
            local_port=port
        )
        if conv.key not in self._bindsocks:
            raise dbus.DBusException('Not listening')

        sock = self._bindsocks.pop(conv.key)
        self.__logger.info('Un-listening on %s:%d', address or '*', port)
        if sock in self._listen_plain:
            glib.source_remove(self._listen_plain.pop(sock))
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except socket.error as err:
            self.__logger.warning('Bind socket shutdown error: %s', err)
        sock.close()

    def polling_start(self, item:PollConfig):
        self.__logger.info('Polling start to %s at interval %sms', item.address, item.interval_ms)
        tid = glib.timeout_add(item.interval_ms, self._poll, item, True)
        if item.interval_ms > 2000:
            # First one immediately
            glib.timeout_add(1000, self._poll, item, False)
        return tid

    @dbus.service.signal(DBUS_IFACE, signature='xissi')
    def polling_received(self, dtntime, interval_ms, node_id, address, port):
        ''' Signal when a receive-path accept is received.
        '''

    def _poll(self, item:PollConfig, repeat:bool):
        ''' Send a return-path accept message.
        '''
        data = cbor2.dumps({
            ExtensionKey.RETURN_ACCEPT: item.interval_ms,
            ExtensionKey.SENDER_NODEID: self._config.node_id,
        })
        item = BundleItem(
            address=item.address,
            port=item.port,
            total_length=len(data),
            file=BytesIO(data),
        )
        self._tx_queue.append(item)
        self._process_tx_queue_trigger()
        return repeat

    def _sock_recvfrom(self, sock, *_args, **_kwargs):
        ''' Callback to handle incoming datagrams.

        :return: True to continue listening.
        '''
        data, fromaddr = sock.recvfrom(64 * 1024)
        localaddr = sock.getsockname()

        conv = Conversation(
            peer_address=Conversation.addr_from_str(fromaddr[0]),
            peer_port=fromaddr[1],
            local_address=Conversation.addr_from_str(localaddr[0]),
            local_port=localaddr[1]
        )
        self.__logger.info('Received %d octets via plain on %s',
                           len(data), conv)
        self._plain_sock[conv.key] = sock
        self._recv_datagram(sock, data, conv)
        return True

    def _starttls(self, sock, conv:Conversation, server_side:bool):
        # ignore plaintext during and after handshake
        if sock in self._listen_plain:
            glib.source_remove(self._listen_plain.pop(sock))

        conn = self._config.get_ssl_connection(sock, server_side=server_side)
        if server_side:
            conn.listen()
        else:
            # as client
            conn.connect(conv.get_peer_addr())

        self.__logger.info('Starting TLS handshake on %s', sock)
        conn.do_handshake()
        # after establishment
        self._dtls_sess[conv.key] = conn

        glib.io_add_watch(
            conn.get_socket(inbound=True),
            glib.IO_IN,
            self._dtlsconn_recv,
            conn, conv
        )

        return conn

    def _dtlsconn_recv(self, _src, _cond, conn, conv:Conversation, *_args, **_kwargs):
        data = conn.read(64 * 1024)
        self.__logger.info('Received %d octets via DTLS on %s',
                           len(data), conv)
        self._recv_datagram(None, data, conv)
        return True

    def _recv_datagram(self, sock, data:bytes, conv:Conversation):
        DTLS_FIRST_OCTETS = (
            20,  # change_cipher_spec
            21,  # alert
            22,  # handshake
            23,  # application_data
        )
        timestamp = datetime.now(timezone.utc)

        first_octet = data[0]
        major_type = first_octet >> 5
        if first_octet == 0x00:
            self.__logger.info('Ignoring padding data')

        elif first_octet in DTLS_FIRST_OCTETS:
            self.__logger.error('Unexpected DTLS handshake')
            if sock:
                self._starttls(sock, conv, server_side=True)
            else:
                self.__logger.error('Ignored DTLS message *within* DTLS plaintext')

        elif first_octet == 0x06:
            if sock and self._config.require_tls:
                self.__logger.error('Rejecting non-secured bundle')
                return

            self.__logger.error('Ignoring BPv6 bundle')

        elif major_type == 4:
            if sock and self._config.require_tls:
                self.__logger.error('Rejecting non-secured bundle')
                return

            self._add_rx_item(
                BundleItem(
                    address=str(conv.peer_address),
                    port=conv.peer_port,
                    total_length=len(data),
                    file=BytesIO(data)
                )
            )

        elif major_type == 5:
            # Map type
            extmap = cbor2.loads(data)
            if ExtensionKey.STARTTLS in extmap:
                if sock:
                    self._starttls(sock, conv, server_side=True)
                else:
                    self.__logger.error('Ignored STARTTLS *within* DTLS plaintext')

            elif sock and self._config.require_tls:
                self.__logger.error('Rejecting non-secured extension map')
                return

            if ExtensionKey.RETURN_ACCEPT in extmap:
                interval_ms = int(extmap[ExtensionKey.RETURN_ACCEPT])
                node_id = extmap.get(ExtensionKey.SENDER_NODEID, '')
                self.__logger.info('Return-Path Accept for %d ms from %s', interval_ms, node_id)
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

        else:
            self.__logger.warn('Ignoring unknown datagram type')

    def _add_rx_item(self, item:BundleItem):
        ''' Add a recevied bundle.
        '''
        if item.transfer_id is None:
            item.transfer_id = copy.copy(self._rx_id)
            self._rx_id += 1

        metadata = {
            'address': item.address,
            'port': item.port,
        }
        if item.local_addr:
            metadata['local_addr'] = item.local_addr
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

    @dbus.service.method(DBUS_IFACE, in_signature='aya{sv}', out_signature='s')
    def send_bundle_data(self, data, tx_params):
        ''' Send bundle data directly.
        '''
        # byte array to bytes
        data = b''.join([bytes([val]) for val in data])
        tx_params = dict(tx_params)
        self.__logger.debug('send_bundle_data data len %d, tx_params %s', len(data), tx_params)

        item = BundleItem(
            address=str(tx_params['address']),
            port=int(tx_params.get('port', 4556)),
            local_addr=(str(tx_params['local_addr']) if 'local_addr' in tx_params else None),
            local_port=(int(tx_params['local_port']) if 'local_port' in tx_params else None),
            file=BytesIO(data)
        )
        return str(self._add_tx_item(item))

    def _add_tx_item(self, item):
        if item.transfer_id is None:
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

        conv = Conversation(
            peer_address=Conversation.addr_from_str(item.address),
            peer_port=item.port,
            local_address=Conversation.addr_from_str(item.local_addr or self._config.default_tx_address),
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

        def simplesender(data):
            ''' Send to a single destination
            '''
            sock.sendto(data, conv.get_peer_addr())

        if conv.peer_address.is_multicast:
            multicast = self._config.multicast

            loop = 0
            if loop is not None:
                if conv.is_ipv4:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
                else:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, loop)

            if multicast.ttl is not None:
                if conv.is_ipv4:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, multicast.ttl)
                else:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, multicast.ttl)

            self._send_transfer(simplesender, item)

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

