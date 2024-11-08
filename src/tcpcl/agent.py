'''
Implementation of a symmetric TCPCL agent.
'''
from dataclasses import dataclass, astuple, field
import logging
from typing import Optional
import ipaddress
import socket
import dbus.service
from gi.repository import GLib as glib

from tcpcl.config import Config, ListenConfig, ConnectConfig
from tcpcl.session import ContactHandler


LOGGER = logging.getLogger(__name__)


class AddressObject:
    ''' Interpret a text address as an `ipaddress` object.

    :param text: The input to convert.
    '''
    def __init__(self, text: Optional[str], proto=socket.IPPROTO_TCP):
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
    ''' Bookkeep parameters of a TCP conversation
    which is address-and-port for each side.
    '''
    # Address family
    family: Optional[int] = None
    # The remote address
    peer_address: Optional[ipaddress._BaseAddress] = None
    # The remote port
    peer_port: Optional[int] = None
    # The local address
    local_address: Optional[ipaddress._BaseAddress] = None
    # The local port
    local_port: Optional[int] = None

    @property
    def key(self):
        return astuple(self)

    def make_socket(self):
        ''' Get a socket based on local requirements.
        :return: A TCP socket object.
        '''
        sock = socket.socket(self.family, socket.SOCK_STREAM, socket.IPPROTO_TCP)

        if self.local_address or self.local_port:
            address = str(self.local_address) if self.local_address else ''
            port = self.local_port or 0
            sock.bind((address, port))

        if self.peer_address and self.peer_port:
            address = str(self.peer_address)
            sock.connect((address, self.peer_port))

        return sock


class Agent(dbus.service.Object):
    ''' Overall agent behavior.

    :param config: The agent configuration object.
    :type config: :py:class:`Config`
    :param bus_kwargs: Arguments to :py:class:`dbus.service.Object` constructor.
        If not provided the default dbus configuration is used.
    :type bus_kwargs: dict or None
    '''

    DBUS_IFACE = 'org.ietf.dtn.tcpcl.Agent'

    def __init__(self, config, bus_kwargs=None):
        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._config = config
        self._on_stop = None
        # Set when shutdown() is called and waiting on sessions
        self._in_shutdown = False

        self._bindsocks = {}
        self._obj_id = 0
        self._handlers = []
        self._path_to_handler = {}

        if bus_kwargs is None:
            bus_kwargs = dict(
                conn=config.bus_conn,
                object_path='/org/ietf/dtn/tcpcl/Agent'
            )
        dbus.service.Object.__init__(self, **bus_kwargs)

        if self._config.bus_service:
            self._bus_serv = dbus.service.BusName(
                bus=self._config.bus_conn,
                name=self._config.bus_service,
                do_not_queue=True
            )
            self._logger.info('Registered as "%s"', self._bus_serv.get_name())

        for item in self._config.init_listen:
            self.listen(item.address, item.port)
        for item in self._config.init_connect:
            self.connect(item.address, item.port)

    def _get_obj_path(self):
        hdl_id = self._obj_id
        self._obj_id += 1
        return '/org/ietf/dtn/tcpcl/Contact{0}'.format(hdl_id)

    def _bind_handler(self, **kwargs):
        ''' Construct a new handler object.

        :param kwargs: The `hdl_kwargs` given to the handler.
        :return: The handler.
        :rtype: :py:cls:`ContactHandler`
        '''
        path = self._get_obj_path()
        hdl = ContactHandler(
            hdl_kwargs=kwargs,
            bus_kwargs=dict(conn=self._config.bus_conn, object_path=path)
        )

        self._handlers.append(hdl)
        self._path_to_handler[path] = hdl
        hdl.set_on_close(lambda: self._unbind_handler(hdl))

        self.connection_opened(path)
        return hdl

    def _unbind_handler(self, hdl):
        path = hdl.object_path
        self.connection_closed(path)
        self._path_to_handler.pop(path)
        self._handlers.remove(hdl)

        if not self._handlers and (self._in_shutdown or self._config.stop_on_close):
            self.stop()

    def set_on_stop(self, func):
        ''' Set a callback to be run when this agent is stopped.

        :param func: The callback, which takes no arguments.
        '''
        self._on_stop = func

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='ao')
    def get_connections(self):
        ''' Get all connections for this agent.
        :return: List of object paths.
        '''
        return self._path_to_handler.keys()

    @dbus.service.signal(DBUS_IFACE, signature='o')
    def connection_opened(self, objpath):
        ''' Emitted when a connection is opened. '''
        self._logger.info('Opened handler at "%s"', objpath)

    @dbus.service.signal(DBUS_IFACE, signature='o')
    def connection_closed(self, objpath):
        ''' Emitted when a connection is closed. '''
        self._logger.info('Closed handler at "%s"', objpath)

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='b')
    def shutdown(self):
        ''' Gracefully terminate all open sessions.
        Once the sessions are closed then the agent may stop.

        :return: True if the agent is stopped immediately or
            False if a wait is needed.
        '''
        self._logger.info('Shutting down agent')
        self._in_shutdown = True
        if not self._handlers:
            self.stop()
            return True

        for hdl in self._handlers:
            hdl.terminate()
        self._logger.info('Waiting on sessions to terminate')
        return False

    @dbus.service.method(DBUS_IFACE, in_signature='')
    def stop(self):
        ''' Immediately stop the agent and disconnect any sessions. '''
        self._logger.info('Stopping agent')
        for spec in tuple(self._bindsocks.keys()):
            conv = Conversation(*spec)
            try:
                self._listen_stop(conv)
            except:
                pass

        for hdl in self._handlers:
            hdl.close()

        if tuple(self.locations):
            self.remove_from_connection()

        if self._on_stop:
            self._on_stop()

    def exec_loop(self):
        ''' Run this agent in an event loop.
        The on_stop callback is replaced to quit the event loop.
        '''
        eloop = glib.MainLoop()
        self.set_on_stop(eloop.quit)
        self._logger.info('Starting event loop')
        try:
            eloop.run()
        except KeyboardInterrupt:
            if not self.shutdown():
                # wait for graceful shutdown
                eloop.run()

    @dbus.service.method(DBUS_IFACE, in_signature='sq')
    def listen(self, address, port):
        ''' Begin listening for incoming connections and defer handling
        connections to `glib` event loop.
        '''
        addrobj = AddressObject(address)
        conv = Conversation(
            family=addrobj.family,
            local_address=addrobj.ipaddr,
            local_port=port
        )
        if conv.key in self._bindsocks:
            raise dbus.DBusException('Already listening on {}:{}'.format(conv.local_address, conv.local_port))

        sock = conv.make_socket()

        self._logger.info('Listening on %s:%d', conv.local_address, conv.local_port)
        sock.listen(1)
        self._bindsocks[conv.key] = sock
        glib.io_add_watch(sock, glib.IO_IN, self._accept)

    @dbus.service.method(DBUS_IFACE, in_signature='sq')
    def listen_stop(self, address, port):
        ''' Stop listening for connections on an existing port binding.
        '''
        addrobj = AddressObject(address)
        conv = Conversation(
            family=addrobj.family,
            local_address=addrobj.ipaddr,
            local_port=port
        )
        return self._listen_stop(conv)

    def _listen_stop(self, conv):
        if conv.key not in self._bindsocks:
            raise dbus.DBusException('Not listening')

        sock = self._bindsocks.pop(conv.key)
        self._logger.info('Un-listening on %s:%d', conv.local_address, conv.local_port)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except socket.error as err:
            self._logger.warning('Bind socket shutdown error: %s', err)
        sock.close()

    def _accept(self, bindsock, *_args, **_kwargs):
        ''' Callback to handle incoming connections.

        :return: True to continue listening.
        '''
        newsock, fromaddr = bindsock.accept()
        self._logger.info('Connecting')
        hdl = self._bind_handler(
            config=self._config, sock=newsock, fromaddr=fromaddr)

        try:
            hdl.start()
        except IOError as err:
            self._logger.warning('Failed: %s', err)

        return True

    @dbus.service.method(DBUS_IFACE, in_signature='sq', out_signature='o')
    def connect(self, address, port):
        ''' Initiate an outgoing connection and defer handling state to
        `glib` event loop.

        :return: The new contact object path.
        :rtype: str
        '''
        addrobj = AddressObject(address)
        conv = Conversation(
            family=addrobj.family,
            peer_address=addrobj.ipaddr,
            peer_port=port
        )
        self._logger.info('Connecting')
        sock = conv.make_socket()

        hdl = self._bind_handler(
            config=self._config,
            sock=sock,
            toaddr=(str(conv.peer_address), conv.peer_port)
        )
        hdl.start()

        return hdl.object_path

    def handler_for_path(self, path):
        ''' Look up a contact by its object path.
        '''
        return self._path_to_handler[path]
